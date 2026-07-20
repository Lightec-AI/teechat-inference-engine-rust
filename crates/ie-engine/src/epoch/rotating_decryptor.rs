//! Multi-epoch decryptor for rotation overlap (port of `rotating-decryptor.ts`).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use ie_crypto::CryptoProvider;
use ie_protocol::OpeEnvelope;

use super::engine_epoch::{dispose_engine_epoch, EngineEpoch};
use crate::EngineError;

pub struct RotatingEpochDecryptor {
    epochs: RwLock<HashMap<String, EngineEpoch>>,
    current_epoch_id: RwLock<Option<String>>,
    overlap_grace_ms: u64,
    provider: Arc<dyn CryptoProvider>,
}

impl RotatingEpochDecryptor {
    pub fn new(initial: EngineEpoch, overlap_grace_ms: u64) -> Self {
        let provider = Arc::clone(&initial.provider);
        let mut epochs = HashMap::new();
        let epoch_id = initial.epoch_id.clone();
        epochs.insert(epoch_id.clone(), initial);
        Self {
            epochs: RwLock::new(epochs),
            current_epoch_id: RwLock::new(Some(epoch_id)),
            overlap_grace_ms,
            provider,
        }
    }

    pub fn provider(&self) -> Arc<dyn CryptoProvider> {
        Arc::clone(&self.provider)
    }

    pub fn handle(&self) -> Result<u64, EngineError> {
        let current = self.current_epoch_id.read().expect("epoch id");
        let epochs = self.epochs.read().expect("epochs");
        let id = current.as_ref().ok_or_else(|| EngineError::Epoch("no current epoch".into()))?;
        let epoch = epochs
            .get(id)
            .ok_or_else(|| EngineError::Epoch(format!("missing epoch {id}")))?;
        epoch
            .handle
            .ok_or_else(|| EngineError::Epoch("current epoch has no native decrypt handle".into()))
    }

    pub fn resolve_handle(&self, envelope: &OpeEnvelope) -> Result<u64, EngineError> {
        let epoch_id = envelope
            .e2e
            .as_ref()
            .and_then(|e2e| {
                if e2e.ephemeral_epoch.is_empty() {
                    None
                } else {
                    Some(e2e.ephemeral_epoch.clone())
                }
            })
            .or_else(|| self.current_epoch_id.read().expect("epoch id").clone());

        let epochs = self.epochs.read().expect("epochs");
        let target = epoch_id
            .as_ref()
            .and_then(|id| epochs.get(id))
            .or_else(|| {
                self.current_epoch_id
                    .read()
                    .expect("epoch id")
                    .as_ref()
                    .and_then(|id| epochs.get(id))
            });

        target
            .and_then(|e| e.handle)
            .ok_or_else(|| {
                EngineError::Epoch(format!(
                    "no decrypt handle for epoch {}",
                    epoch_id.unwrap_or_else(|| "current".into())
                ))
            })
    }

    pub fn add_epoch(&self, epoch: EngineEpoch) {
        let id = epoch.epoch_id.clone();
        self.epochs.write().expect("epochs").insert(id.clone(), epoch);
        *self.current_epoch_id.write().expect("epoch id") = Some(id);
    }

    pub fn current_epoch_id(&self) -> Option<String> {
        self.current_epoch_id.read().expect("epoch id").clone()
    }

    pub fn prune_retired(&self, now_ms: u64, overlap_grace_ms: Option<u64>) {
        let grace = overlap_grace_ms.unwrap_or(self.overlap_grace_ms);
        let current = self.current_epoch_id.read().expect("epoch id").clone();
        let mut epochs = self.epochs.write().expect("epochs");
        let retired: Vec<String> = epochs
            .iter()
            .filter_map(|(id, epoch)| {
                if current.as_deref() == Some(id.as_str()) {
                    return None;
                }
                let end = crate::ops::parse_iso_time_ms(&epoch.not_after)?;
                if now_ms > end.saturating_add(grace) {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect();
        for id in retired {
            if let Some(epoch) = epochs.remove(&id) {
                dispose_engine_epoch(&epoch);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::epoch::create_engine_epoch;
    use crate::epoch::CreateEngineEpochArgs;
    use ie_crypto::MockCryptoProvider;
    use ie_protocol::OpeE2eDescriptor;
    use ope_crypto::{mock_keypair_from_seed, DEV_VECTOR_001_SEED};

    fn sample_epoch(id: &str, ttl_ms: u64) -> EngineEpoch {
        let provider = Arc::new(MockCryptoProvider::new());
        let kp = mock_keypair_from_seed(&DEV_VECTOR_001_SEED);
        let pub_b64 = ope_crypto::encode(kp.public.to_bytes().as_slice());
        create_engine_epoch(CreateEngineEpochArgs {
            engine_id: "eng",
            ed25519_public_b64: &pub_b64,
            signing_key: &kp.secret,
            attestation: None,
            epoch_id: Some(id.into()),
            ttl_ms: Some(ttl_ms),
            provider,
        })
        .unwrap()
    }

    fn sample_envelope(epoch: &str) -> OpeEnvelope {
        OpeEnvelope {
            ope_version: "1".into(),
            alg: "a".into(),
            enc: "e".into(),
            kid: "k".into(),
            recipient: "r".into(),
            ts: "t".into(),
            nonce: "n".into(),
            payload_hash: "h".into(),
            engine_id: None,
            meta: None,
            sig: None,
            ciphertext: None,
            iv: None,
            e2e: Some(OpeE2eDescriptor {
                kex: "x".into(),
                client_share: None,
                engine_mlkem_encap: "m".into(),
                engine_x25519: "x".into(),
                ephemeral_epoch: epoch.into(),
                content_alg: None,
                mlkem_ciphertext: None,
                client_x25519: None,
                server_share: None,
            }),
        }
    }

    #[test]
    fn rotating_epoch_decryptor_tracks_current_handle() {
        let epoch_a = sample_epoch("epoch-a", 60_000);
        let handle_a = epoch_a.handle;
        let decryptor = RotatingEpochDecryptor::new(epoch_a, 0);
        assert_eq!(decryptor.current_epoch_id(), Some("epoch-a".into()));

        let epoch_b = sample_epoch("epoch-b", 60_000);
        decryptor.add_epoch(epoch_b);
        assert_eq!(decryptor.current_epoch_id(), Some("epoch-b".into()));

        let envelope = sample_envelope("epoch-a");
        if let Some(h) = handle_a {
            assert_eq!(decryptor.resolve_handle(&envelope).unwrap(), h);
        }
    }

    #[test]
    fn rotating_epoch_decryptor_prunes_retired_epochs() {
        let epoch_a = sample_epoch("epoch-a", 1);
        let end_ms = crate::ops::parse_iso_time_ms(&epoch_a.not_after).unwrap();
        let decryptor = RotatingEpochDecryptor::new(epoch_a, 0);
        let epoch_b = sample_epoch("epoch-b", 60_000);
        decryptor.add_epoch(epoch_b);
        decryptor.prune_retired(end_ms + 2, Some(0));
        let envelope = sample_envelope("epoch-a");
        assert!(decryptor.resolve_handle(&envelope).is_err());
    }
}
