//! Fixture production quote backend for CI (port of `attestation-fixture-backend.ts`).

use std::collections::HashSet;
use std::sync::{Arc, Mutex, OnceLock};

use ie_protocol::CpuTeeKind;

use crate::claims::QuoteClaims;
use crate::mock_quote::parse_mock_cpu_quote;
use crate::verify::{CpuQuoteVerifier, VerifyError};

pub const FIXTURE_INTEL_TDX_QUOTE_PLACEHOLDER: &str = "fixture-intel-tdx-v1-not-real-hardware";

pub type ProductionQuoteBackend =
    Arc<dyn Fn(&str, CpuTeeKind) -> Option<QuoteClaims> + Send + Sync>;

static PRODUCTION_BACKEND: OnceLock<Mutex<Option<ProductionQuoteBackend>>> = OnceLock::new();

fn backend_slot() -> &'static Mutex<Option<ProductionQuoteBackend>> {
    PRODUCTION_BACKEND.get_or_init(|| Mutex::new(None))
}

pub fn register_production_quote_backend(backend: ProductionQuoteBackend) {
    *backend_slot().lock().expect("backend") = Some(backend);
}

pub fn clear_production_quote_backend() {
    *backend_slot().lock().expect("backend") = None;
}

pub fn is_production_quote_backend_registered() -> bool {
    backend_slot().lock().expect("backend").is_some()
}

pub fn create_fixture_production_quote_backend(
    allowed_quotes: HashSet<String>,
) -> ProductionQuoteBackend {
    let allowed = if allowed_quotes.is_empty() {
        HashSet::from([FIXTURE_INTEL_TDX_QUOTE_PLACEHOLDER.to_string()])
    } else {
        allowed_quotes
    };
    Arc::new(move |quote: &str, expected_kind: CpuTeeKind| {
        if allowed.contains(quote) {
            if expected_kind != CpuTeeKind::Tdx {
                return None;
            }
            return Some(QuoteClaims {
                v: 1,
                kind: CpuTeeKind::Tdx,
                ed25519_public: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
                tls_client_cert_sha256: String::new(),
                engine: ie_protocol::WorkloadMeasurements {
                    version: "fixture".into(),
                    binary_sha256:
                        "a1b2c3d4e5f6789012345678abcdef9012345678abcdef9012345678abcdef90".into(),
                },
                vllm: ie_protocol::WorkloadMeasurements {
                    version: "fixture".into(),
                    binary_sha256:
                        "b2c3d4e5f6789012345678abcdef9012345678abcdef9012345678abcdef9012".into(),
                },
                ope: None,
                attested_mtls: None,
                issued_at: chrono::Utc::now().to_rfc3339(),
            });
        }
        let claims = parse_mock_cpu_quote(quote)?;
        if claims.kind == expected_kind {
            Some(claims)
        } else {
            None
        }
    })
}

pub struct MockCpuQuoteVerifier;

impl CpuQuoteVerifier for MockCpuQuoteVerifier {
    fn kind(&self) -> &'static str {
        "mock"
    }

    fn extract_claims(
        &self,
        quote: &str,
        _expected_kind: CpuTeeKind,
    ) -> Result<QuoteClaims, VerifyError> {
        parse_mock_cpu_quote(quote).ok_or(VerifyError::InvalidQuote)
    }
}

pub struct ProductionCpuQuoteVerifier;

impl CpuQuoteVerifier for ProductionCpuQuoteVerifier {
    fn kind(&self) -> &'static str {
        "production"
    }

    fn extract_claims(
        &self,
        quote: &str,
        expected_kind: CpuTeeKind,
    ) -> Result<QuoteClaims, VerifyError> {
        let backend = backend_slot().lock().expect("backend");
        let Some(backend) = backend.as_ref() else {
            return Err(VerifyError::NoProductionBackend);
        };
        backend(quote, expected_kind).ok_or(VerifyError::InvalidQuote)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_backend_extracts_placeholder_quote() {
        register_production_quote_backend(create_fixture_production_quote_backend(HashSet::new()));
        let verifier = ProductionCpuQuoteVerifier;
        let claims = verifier
            .extract_claims(FIXTURE_INTEL_TDX_QUOTE_PLACEHOLDER, CpuTeeKind::Tdx)
            .unwrap();
        assert_eq!(claims.kind, CpuTeeKind::Tdx);
        clear_production_quote_backend();
    }
}
