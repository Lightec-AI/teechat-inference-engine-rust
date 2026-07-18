use async_trait::async_trait;
use serde::Serialize;
use serde_json::Value;

use super::error::PlaneError;

#[derive(Debug, Clone)]
pub struct H2JsonResponse {
    pub status: u16,
    pub json: Value,
}

/// Abstract long-lived engine-plane session transport (one HTTP/2 connection).
#[async_trait]
pub trait PlaneTransport: Send + Sync {
    async fn request_json(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
        headers: &[(&str, &str)],
    ) -> Result<H2JsonResponse, PlaneError>;

    async fn close(self: Box<Self>) -> Result<(), PlaneError>;
}

/// Live attested session owning the transport.
pub struct AttestedH2Session {
    session_id: String,
    transport: Box<dyn PlaneTransport>,
}

impl AttestedH2Session {
    pub fn from_transport(session_id: String, transport: Box<dyn PlaneTransport>) -> Self {
        Self {
            session_id,
            transport,
        }
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub async fn request_json(
        &self,
        method: &str,
        path: &str,
        body: Option<&impl Serialize>,
        headers: &[(&str, &str)],
    ) -> Result<H2JsonResponse, PlaneError> {
        let value = match body {
            Some(b) => Some(serde_json::to_value(b)?),
            None => None,
        };
        self.transport
            .request_json(method, path, value.as_ref(), headers)
            .await
    }

    pub async fn close(self) -> Result<(), PlaneError> {
        self.transport.close().await
    }
}
