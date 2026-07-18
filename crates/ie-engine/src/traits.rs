use async_trait::async_trait;

use ie_protocol::{AttestedConnectRequest, AttestedConnectResponse};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectResult {
    pub session_id: String,
    pub response: AttestedConnectResponse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InferResult {
    pub completion: String,
    pub finish_reason: Option<String>,
}

/// Attested TLS engine-plane dial + control/connect (port of `engine-plane/pool-client.ts`).
#[async_trait]
pub trait EnginePlaneConnector: Send + Sync {
    async fn connect(
        &self,
        request: AttestedConnectRequest,
    ) -> Result<ConnectResult, Box<dyn std::error::Error + Send + Sync>>;

    async fn disconnect(&self, session_id: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// vLLM / OpenAI-compatible inference upstream (port of `upstream/vllm-chat.ts` usage site).
#[async_trait]
pub trait InferenceUpstream: Send + Sync {
    async fn infer_chat(
        &self,
        model: &str,
        prompt: &str,
    ) -> Result<InferResult, Box<dyn std::error::Error + Send + Sync>>;
}
