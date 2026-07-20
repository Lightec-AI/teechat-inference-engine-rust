//! SEV-SNP quote wrapper v2 (port of `sev-snp/quote.ts`).

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;

use crate::claims::QuoteClaims;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct SevSnpQuoteWrapper {
    pub v: u8,
    pub kind: String,
    pub report_b64: String,
    pub report_data_b64: String,
    pub claims: QuoteClaims,
}

pub fn bind_report_data_64(
    ed25519_public: &str,
    tls_client_cert_sha256: &str,
    engine_binary_sha256: &str,
    vllm_binary_sha256: &str,
    issued_at: &str,
    nonce: Option<&str>,
) -> [u8; 64] {
    let canonical = [
        "teechat-sev-snp-bind-v1",
        ed25519_public,
        &tls_client_cert_sha256.to_ascii_lowercase(),
        &engine_binary_sha256.to_ascii_lowercase(),
        &vllm_binary_sha256.to_ascii_lowercase(),
        issued_at,
        nonce.unwrap_or(""),
    ]
    .join("\0");
    let digest = Sha512::digest(canonical.as_bytes());
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest[..64]);
    out
}

pub fn encode_sev_snp_quote_wrapper(wrapper: &SevSnpQuoteWrapper) -> String {
    let json = serde_json::to_vec(wrapper).expect("wrapper json");
    ope_crypto::encode(&json)
}

pub fn parse_sev_snp_quote_wrapper(quote: &str) -> Option<SevSnpQuoteWrapper> {
    let raw = ope_crypto::decode(quote).ok()?;
    let parsed: SevSnpQuoteWrapper = serde_json::from_slice(&raw).ok()?;
    if parsed.v != 2 || parsed.kind != "sev-snp" {
        return None;
    }
    if parsed.report_b64.is_empty()
        || parsed.report_data_b64.is_empty()
        || parsed.claims.kind != ie_protocol::CpuTeeKind::SevSnp
    {
        return None;
    }
    Some(parsed)
}

pub fn verify_wrapper_report_data(wrapper: &SevSnpQuoteWrapper, nonce: Option<&str>) -> bool {
    // Match TS: report_data_b64 is standard base64 (not base64url).
    let data = match STANDARD.decode(&wrapper.report_data_b64) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if data.len() != 64 {
        return false;
    }
    let expected = bind_report_data_64(
        &wrapper.claims.ed25519_public,
        &wrapper.claims.tls_client_cert_sha256,
        &wrapper.claims.engine.binary_sha256,
        &wrapper.claims.vllm.binary_sha256,
        &wrapper.claims.issued_at,
        nonce,
    );
    data.as_slice().ct_eq(&expected).unwrap_u8() == 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use ie_protocol::{CpuTeeKind, WorkloadMeasurements};

    #[test]
    fn bind_report_data_64_is_64_bytes() {
        let data = bind_report_data_64("pub", "tls", "eng", "vllm", "ts", None);
        assert_eq!(data.len(), 64);
    }

    #[test]
    fn encode_parse_roundtrip() {
        let wrapper = SevSnpQuoteWrapper {
            v: 2,
            kind: "sev-snp".into(),
            report_b64: "cm".into(),
            report_data_b64: STANDARD.encode([0u8; 64]),
            claims: QuoteClaims {
                v: 1,
                kind: CpuTeeKind::SevSnp,
                ed25519_public: "pub".into(),
                tls_client_cert_sha256: String::new(),
                engine: WorkloadMeasurements {
                    version: "e".into(),
                    binary_sha256: "a".repeat(64),
                },
                vllm: WorkloadMeasurements {
                    version: "v".into(),
                    binary_sha256: "b".repeat(64),
                },
                ope: None,
                attested_mtls: None,
                issued_at: "2026-01-01T00:00:00Z".into(),
            },
        };
        let encoded = encode_sev_snp_quote_wrapper(&wrapper);
        let parsed = parse_sev_snp_quote_wrapper(&encoded).expect("parse");
        assert_eq!(parsed.v, 2);
    }
}
