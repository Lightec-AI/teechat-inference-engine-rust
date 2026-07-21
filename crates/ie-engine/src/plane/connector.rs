use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use std::sync::Arc;

use ie_protocol::{
    AttestedConnectRequest, AttestedDisconnectReason, EngineEphemeralRegisterRequest,
};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::plane::challenge::generate_gateway_connect_challenge_nonce;
use crate::plane::ephemeral::post_ephemeral_on_attested_session;
use crate::traits::{ConnectResult, EnginePlaneConnector};

use super::connect::{open_pooled_connection, EnginePlaneDialOptions};
use super::disconnect::graceful_disconnect_attested_session;
use super::error::PlaneError;
use super::session::{AttestedH2Session, PlaneTransport};

/// Concrete HTTP/2 engine-plane connector owning live sessions.
pub struct Http2EnginePlaneConnector {
    dial: Mutex<EnginePlaneDialOptions>,
    sessions: Mutex<HashMap<String, AttestedH2Session>>,
    disconnect_timeout: Duration,
    disconnect_poll: Duration,
}

impl Http2EnginePlaneConnector {
    pub fn new(dial: EnginePlaneDialOptions) -> Self {
        Self {
            dial: Mutex::new(dial),
            sessions: Mutex::new(HashMap::new()),
            disconnect_timeout: Duration::from_secs(120),
            disconnect_poll: Duration::from_millis(250),
        }
    }

    pub fn with_disconnect_timing(mut self, timeout: Duration, poll_interval: Duration) -> Self {
        self.disconnect_timeout = timeout;
        self.disconnect_poll = poll_interval;
        self
    }

    /// Update the default dial URL (e.g. after full migration).
    pub async fn set_gateway_base_url(&self, url: impl Into<String>) {
        self.dial.lock().await.gateway_base_url = url.into();
    }

    pub async fn gateway_base_url(&self) -> String {
        self.dial.lock().await.gateway_base_url.clone()
    }

    pub async fn transport(&self, session_id: &str) -> Option<Arc<dyn PlaneTransport>> {
        self.sessions
            .lock()
            .await
            .get(session_id)
            .map(|s| s.transport())
    }

    pub async fn post_ephemeral(
        &self,
        session_id: &str,
        body: &EngineEphemeralRegisterRequest,
    ) -> Result<u16, String> {
        let transport = self
            .transport(session_id)
            .await
            .ok_or_else(|| format!("unknown session {session_id}"))?;
        let session = AttestedH2Session::from_arc(session_id.to_string(), transport);
        let resp = post_ephemeral_on_attested_session(&session, body)
            .await
            .map_err(|e| e.to_string())?;
        Ok(resp.status)
    }

    async fn connect_inner(
        &self,
        gateway_base_url: Option<&str>,
        request: AttestedConnectRequest,
        preserve_session_id: Option<String>,
    ) -> Result<ConnectResult, Box<dyn std::error::Error + Send + Sync>> {
        // Fresh id for boot/scale/migrate. Reconnect keeps the slot session id (TS affinity).
        let session_id = preserve_session_id.unwrap_or_else(|| Uuid::new_v4().to_string());

        let mut dial = self.dial.lock().await.clone();
        if let Some(url) = gateway_base_url {
            dial.gateway_base_url = url.trim().to_string();
        }
        dial.connect_template = request;
        dial.connect_template.session_id = session_id.clone();
        if dial.pool_target_size == 0 {
            dial.pool_target_size = dial.connect_template.pool_target_size.unwrap_or(1);
        }

        // Fresh nonce per dial (template may be reused across pool connects).
        let nonce = generate_gateway_connect_challenge_nonce();
        dial.gateway_challenge_nonce = Some(nonce.clone());
        dial.connect_template.gateway_challenge_nonce = Some(nonce);

        let (session, response) = open_pooled_connection(&dial, &session_id)
            .await
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;

        self.sessions
            .lock()
            .await
            .insert(session_id.clone(), session);

        Ok(ConnectResult {
            session_id,
            response,
        })
    }

    async fn disconnect_with_reason(
        &self,
        session_id: &str,
        reason: AttestedDisconnectReason,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let session = self
            .sessions
            .lock()
            .await
            .remove(session_id)
            .ok_or_else(|| PlaneError::UnknownSession(session_id.to_string()))
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;

        let engine_id = self.dial.lock().await.connect_template.engine_id.clone();
        let result = graceful_disconnect_attested_session(
            &session,
            &engine_id,
            reason,
            self.disconnect_timeout,
            self.disconnect_poll,
        )
        .await;
        let _ = session.close().await;
        result.map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })
    }
}

#[async_trait]
impl EnginePlaneConnector for Http2EnginePlaneConnector {
    async fn connect(
        &self,
        request: AttestedConnectRequest,
    ) -> Result<ConnectResult, Box<dyn std::error::Error + Send + Sync>> {
        self.connect_inner(None, request, None).await
    }

    async fn connect_to(
        &self,
        gateway_base_url: &str,
        request: AttestedConnectRequest,
    ) -> Result<ConnectResult, Box<dyn std::error::Error + Send + Sync>> {
        self.connect_inner(Some(gateway_base_url), request, None)
            .await
    }

    async fn set_primary_gateway_url(&self, gateway_base_url: &str) {
        self.set_gateway_base_url(gateway_base_url).await;
    }

    async fn disconnect(
        &self,
        session_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.disconnect_with_reason(session_id, AttestedDisconnectReason::Upgrade)
            .await
    }

    async fn is_session_closed(&self, session_id: &str) -> bool {
        match self.sessions.lock().await.get(session_id) {
            Some(session) => session.transport().is_closed(),
            None => true,
        }
    }

    async fn teardown_for_reconnect(
        &self,
        session_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // TS reconnectSlot: gracefulDisconnect(..., "admin") then session.close().
        match self
            .disconnect_with_reason(session_id, AttestedDisconnectReason::Admin)
            .await
        {
            Ok(()) => Ok(()),
            Err(_) => {
                // Transport may already be dead — drop map entry if still present.
                if let Some(session) = self.sessions.lock().await.remove(session_id) {
                    let _ = session.close().await;
                }
                Ok(())
            }
        }
    }

    async fn reconnect(
        &self,
        session_id: &str,
        gateway_base_url: &str,
        request: AttestedConnectRequest,
    ) -> Result<ConnectResult, Box<dyn std::error::Error + Send + Sync>> {
        // Ensure stale map entry is gone before re-inserting the same id.
        if let Some(session) = self.sessions.lock().await.remove(session_id) {
            let _ = session.close().await;
        }
        self.connect_inner(
            Some(gateway_base_url),
            request,
            Some(session_id.to_string()),
        )
        .await
    }
}
