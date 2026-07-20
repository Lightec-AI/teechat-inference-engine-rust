use async_trait::async_trait;
use ie_protocol::{AttestedConnectRequest, AttestedConnectResponse};
use ie_upstream::{VllmChatClient, VllmCompleteOptions};
use serde_json::{json, Value};

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

    /// Dial a specific gateway base URL (make-before-break migration).
    ///
    /// Default: call [`Self::connect`] (single-URL connectors).
    async fn connect_to(
        &self,
        _gateway_base_url: &str,
        request: AttestedConnectRequest,
    ) -> Result<ConnectResult, Box<dyn std::error::Error + Send + Sync>> {
        self.connect(request).await
    }

    async fn disconnect(
        &self,
        session_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
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

#[async_trait]
impl InferenceUpstream for VllmChatClient {
    async fn infer_chat(
        &self,
        model: &str,
        prompt: &str,
    ) -> Result<InferResult, Box<dyn std::error::Error + Send + Sync>> {
        let messages: Vec<Value> = vec![json!({"role": "user", "content": prompt})];
        let completion = self
            .complete_chat(VllmCompleteOptions {
                base_url: std::env::var("TEECHAT_VLLM_BASE_URL")
                    .or_else(|_| std::env::var("VLLM_BASE_URL"))
                    .unwrap_or_else(|_| "http://127.0.0.1:8000".into()),
                model: model.to_string(),
                messages,
                api_key: std::env::var("TEECHAT_VLLM_API_KEY")
                    .or_else(|_| std::env::var("VLLM_API_KEY"))
                    .ok(),
                max_tokens: None,
                frequency_penalty: None,
                presence_penalty: None,
                temperature: None,
                top_p: None,
                enable_thinking: None,
            })
            .await
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
        Ok(InferResult {
            completion,
            finish_reason: Some("stop".into()),
        })
    }
}
