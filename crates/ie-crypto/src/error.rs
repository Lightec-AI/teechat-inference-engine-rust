use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("ope feature disabled; rebuild with `--features ope`")]
    OpeDisabled,
    #[cfg(feature = "ope")]
    #[error("ope-e2e error: {0}")]
    E2e(#[from] ope_e2e::Error),
}
