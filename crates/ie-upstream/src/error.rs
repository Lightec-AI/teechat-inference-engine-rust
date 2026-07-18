use thiserror::Error;

#[derive(Debug, Error)]
pub enum UpstreamError {
    #[error("vLLM HTTP {status}: {body}")]
    Http { status: u16, body: String },
    #[error("vLLM response missing body")]
    MissingBody,
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("invalid SSE chunk: {0}")]
    InvalidSse(String),
}
