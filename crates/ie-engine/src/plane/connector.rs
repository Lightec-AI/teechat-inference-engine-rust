use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use ie_protocol::{AttestedConnectRequest, AttestedDisconnectReason};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::traits::{ConnectResult, EnginePlaneConnector};

use super::connect::{open_pooled_connection, EnginePlaneDialOptions};
use super::disconnect::graceful_disconnect_attested_session;
use super::error::PlaneError;
use super::session::AttestedH2Session;

/// Concrete HTTP/2 engine-plane connector owning live sessions.
pub struct Http2EnginePlaneConnector {
    dial: EnginePlaneDialOptions,
    sessions: Mutex<HashMap<String, AttestedH2Session>>,
    disconnect_timeout: Duration,
    disconnect_poll: Duration,
}

impl Http2EnginePlaneConnector {
    pub fn new(dial: EnginePlaneDialOptions) -> Self {
        Self {
            dial,
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
}

#[async_trait]
impl EnginePlaneConnector for Http2EnginePlaneConnector {
    async fn connect(
        &self,
        request: AttestedConnectRequest,
    ) -> Result<ConnectResult, Box<dyn std::error::Error + Send + Sync>> {
        let session_id = if request.session_id.trim().is_empty() {
            Uuid::new_v4().to_string()
        } else {
            request.session_id.clone()
        };

        let mut dial = self.dial.clone();
        dial.connect_template = request;
        if dial.pool_target_size == 0 {
            dial.pool_target_size = dial.connect_template.pool_target_size.unwrap_or(1);
        }

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

    async fn disconnect(
        &self,
        session_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let session = self
            .sessions
            .lock()
            .await
            .remove(session_id)
            .ok_or_else(|| PlaneError::UnknownSession(session_id.to_string()))
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;

        let engine_id = self.dial.connect_template.engine_id.clone();
        let result = graceful_disconnect_attested_session(
            &session,
            &engine_id,
            AttestedDisconnectReason::Shutdown,
            self.disconnect_timeout,
            self.disconnect_poll,
        )
        .await;
        let _ = session.close().await;
        result.map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })
    }
}
