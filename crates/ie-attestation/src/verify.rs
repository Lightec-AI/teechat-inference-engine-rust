//! CPU quote verifier seam.

use ie_protocol::CpuTeeKind;

use crate::claims::QuoteClaims;

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("invalid or unverifiable quote")]
    InvalidQuote,
    #[error("production quote backend not registered")]
    NoProductionBackend,
}

pub trait CpuQuoteVerifier: Send + Sync {
    fn kind(&self) -> &'static str;
    fn extract_claims(
        &self,
        quote: &str,
        expected_kind: CpuTeeKind,
    ) -> Result<QuoteClaims, VerifyError>;
}
