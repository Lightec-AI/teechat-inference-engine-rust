use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("ope feature disabled; rebuild with `--features ope`")]
    OpeDisabled,
    #[cfg(feature = "ope")]
    #[error("ope-e2e error: {0}")]
    E2e(#[from] ope_e2e::Error),
    #[error("e2e: {0}")]
    E2eMsg(String),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid key material: {0}")]
    InvalidKey(String),
    #[error("unknown engine handle {0}")]
    UnknownHandle(u64),
    #[error("unknown response session {0}")]
    UnknownSession(u64),
    #[error("MockCryptoProvider cannot {0}: use real provider for E2E")]
    MockUnsupported(String),
}
