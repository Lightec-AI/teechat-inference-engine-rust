//! Ephemeral epoch rotation loop (port of `epoch-rotator.ts`).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use ie_crypto::CryptoProvider;
use ie_protocol::{AttestationBundle, EngineEphemeralRegisterRequest};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::sleep;

use super::engine_epoch::{create_engine_epoch, CreateEngineEpochArgs, EngineEpoch};
use super::policy::{
    compute_epoch_rotate_at_ms, epoch_rotation_lead_ms_from_env, epoch_rotation_policy_from_env,
    epoch_ttl_ms_from_policy, EpochRotationPolicy,
};
use crate::EngineError;

#[derive(Debug, Clone)]
pub struct EpochRotatorSession {
    pub session_id: String,
}

#[async_trait::async_trait]
pub trait EphemeralPoster: Send + Sync {
    async fn post_ephemeral(
        &self,
        session_id: &str,
        body: &EngineEphemeralRegisterRequest,
    ) -> Result<u16, String>;
}

pub type EpochRotatedCallback = Arc<dyn Fn(&EngineEpoch, Option<&EngineEpoch>) + Send + Sync>;

pub struct EpochRotator {
    engine_id: String,
    ed25519_public_b64: String,
    signing_key: SigningKey,
    provider: Arc<dyn CryptoProvider>,
    _policy: EpochRotationPolicy,
    lead_ms: u64,
    ttl_ms: u64,
    list_sessions: Arc<dyn Fn() -> Vec<EpochRotatorSession> + Send + Sync>,
    poster: Arc<dyn EphemeralPoster>,
    attestation: RwLock<Option<AttestationBundle>>,
    current: RwLock<EngineEpoch>,
    rotating: Mutex<bool>,
    stopped: RwLock<bool>,
    timer: Mutex<Option<JoinHandle<()>>>,
    on_epoch_rotated: Option<EpochRotatedCallback>,
}

impl EpochRotator {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        engine_id: impl Into<String>,
        ed25519_public_b64: impl Into<String>,
        signing_key: SigningKey,
        provider: Arc<dyn CryptoProvider>,
        attestation: Option<AttestationBundle>,
        env: &HashMap<String, String>,
        list_sessions: Arc<dyn Fn() -> Vec<EpochRotatorSession> + Send + Sync>,
        poster: Arc<dyn EphemeralPoster>,
        on_epoch_rotated: Option<EpochRotatedCallback>,
    ) -> Result<Self, EngineError> {
        let engine_id = engine_id.into();
        let ed25519_public_b64 = ed25519_public_b64.into();
        let policy = epoch_rotation_policy_from_env(env);
        let lead_ms = epoch_rotation_lead_ms_from_env(env);
        let ttl_ms = epoch_ttl_ms_from_policy(&policy);
        let current = create_engine_epoch(CreateEngineEpochArgs {
            engine_id: &engine_id,
            ed25519_public_b64: &ed25519_public_b64,
            signing_key: &signing_key,
            attestation: attestation.clone(),
            epoch_id: None,
            ttl_ms: Some(ttl_ms),
            provider: Arc::clone(&provider),
        })?;
        Ok(Self {
            engine_id,
            ed25519_public_b64,
            signing_key,
            provider,
            _policy: policy,
            lead_ms,
            ttl_ms,
            list_sessions,
            poster,
            attestation: RwLock::new(attestation),
            current: RwLock::new(current),
            rotating: Mutex::new(false),
            stopped: RwLock::new(false),
            timer: Mutex::new(None),
            on_epoch_rotated,
        })
    }

    pub fn current_epoch(&self) -> EngineEpoch {
        self.current.read().expect("current epoch").clone()
    }

    pub fn set_attestation(&self, bundle: AttestationBundle) {
        *self.attestation.write().expect("attestation") = Some(bundle);
    }

    pub async fn register_initial_epoch(&self) -> Result<(), EngineError> {
        self.post_epoch_to_sessions(&self.current_epoch()).await
    }

    /// Register the current epoch on a single session (scale / reconnect).
    pub async fn register_epoch_on_session(&self, session_id: &str) -> Result<(), EngineError> {
        let epoch = self.current_epoch();
        match self
            .poster
            .post_ephemeral(session_id, &epoch.ephemeral_request)
            .await
        {
            Ok(201) => Ok(()),
            Ok(status) => Err(EngineError::Epoch(format!(
                "ephemeral register HTTP {status}"
            ))),
            Err(err) => Err(EngineError::Epoch(err)),
        }
    }

    pub async fn start(self: &Arc<Self>) {
        let this = Arc::clone(self);
        let handle = tokio::spawn(async move {
            this.schedule_loop().await;
        });
        *self.timer.lock().await = Some(handle);
    }

    pub async fn stop(&self) {
        *self.stopped.write().expect("stopped") = true;
        if let Some(handle) = self.timer.lock().await.take() {
            handle.abort();
        }
    }

    pub async fn rotate_now(&self) -> Result<(), EngineError> {
        self.rotate_internal().await
    }

    async fn schedule_loop(self: Arc<Self>) {
        loop {
            if *self.stopped.read().expect("stopped") {
                break;
            }
            let current = self.current_epoch();
            let now_ms = chrono::Utc::now().timestamp_millis() as u64;
            let at = compute_epoch_rotate_at_ms(&current.not_after, self.lead_ms, now_ms);
            let delay = at.saturating_sub(now_ms);
            sleep(Duration::from_millis(delay)).await;
            if *self.stopped.read().expect("stopped") {
                break;
            }
            if let Err(err) = self.rotate_internal().await {
                tracing::warn!(error = %err, "epoch rotation failed; retry in 30s");
                sleep(Duration::from_secs(30)).await;
            }
        }
    }

    async fn post_epoch_to_sessions(&self, epoch: &EngineEpoch) -> Result<(), EngineError> {
        let sessions = (self.list_sessions)();
        if sessions.is_empty() {
            return Err(EngineError::Epoch(
                "no live attested sessions for ephemeral register".into(),
            ));
        }
        let mut last_error = None;
        for session in sessions {
            match self
                .poster
                .post_ephemeral(&session.session_id, &epoch.ephemeral_request)
                .await
            {
                Ok(201) => {}
                Ok(status) => {
                    last_error = Some(format!("ephemeral register HTTP {status}"));
                }
                Err(err) => last_error = Some(err),
            }
        }
        if let Some(err) = last_error {
            return Err(EngineError::Epoch(err));
        }
        Ok(())
    }

    async fn rotate_internal(&self) -> Result<(), EngineError> {
        let mut rotating = self.rotating.lock().await;
        if *rotating || *self.stopped.read().expect("stopped") {
            return Ok(());
        }
        *rotating = true;
        drop(rotating);

        let previous = self.current_epoch();
        let attestation = self.attestation.read().expect("attestation").clone();
        let next = create_engine_epoch(CreateEngineEpochArgs {
            engine_id: &self.engine_id,
            ed25519_public_b64: &self.ed25519_public_b64,
            signing_key: &self.signing_key,
            attestation,
            epoch_id: None,
            ttl_ms: Some(self.ttl_ms),
            provider: Arc::clone(&self.provider),
        })?;

        self.post_epoch_to_sessions(&next).await?;
        if let Some(cb) = &self.on_epoch_rotated {
            cb(&next, Some(&previous));
        }
        *self.current.write().expect("current epoch") = next;

        let mut rotating = self.rotating.lock().await;
        *rotating = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ie_crypto::MockCryptoProvider;
    use ope_crypto::{mock_keypair_from_seed, DEV_VECTOR_001_SEED};

    struct OkPoster;

    #[async_trait::async_trait]
    impl EphemeralPoster for OkPoster {
        async fn post_ephemeral(
            &self,
            _session_id: &str,
            _body: &EngineEphemeralRegisterRequest,
        ) -> Result<u16, String> {
            Ok(201)
        }
    }

    #[tokio::test]
    async fn epoch_rotator_registers_initial_epoch() {
        let provider = Arc::new(MockCryptoProvider::new());
        let kp = mock_keypair_from_seed(&DEV_VECTOR_001_SEED);
        let pub_b64 = ope_crypto::encode(kp.public.to_bytes().as_slice());
        let rotator = Arc::new(
            EpochRotator::new(
                "eng",
                pub_b64,
                kp.secret,
                provider,
                None,
                &HashMap::new(),
                Arc::new(|| vec![EpochRotatorSession {
                    session_id: "s1".into(),
                }]),
                Arc::new(OkPoster),
                None,
            )
            .unwrap(),
        );
        rotator.register_initial_epoch().await.unwrap();
    }
}
