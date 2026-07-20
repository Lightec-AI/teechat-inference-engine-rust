//! HMAC mock CPU quotes for dev/CI (port of `attestation.ts` mock helpers).

use hmac::{Hmac, Mac};
use ope_crypto::decode;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::claims::QuoteClaims;

type HmacSha256 = Hmac<Sha256>;

const MOCK_ATTEST_HMAC_SECRET: &[u8] = b"teechat-mock-ope-attest-v1";

pub fn build_mock_cpu_quote(payload: &QuoteClaims) -> String {
    let body = serde_json::to_vec(payload).expect("quote claims json");
    let mut mac = HmacSha256::new_from_slice(MOCK_ATTEST_HMAC_SECRET).expect("hmac key");
    mac.update(&body);
    let digest = mac.finalize().into_bytes();
    let mut out = body;
    out.extend_from_slice(&digest);
    ope_crypto::encode(&out)
}

pub fn parse_mock_cpu_quote(quote: &str) -> Option<QuoteClaims> {
    let raw = decode(quote).ok()?;
    if raw.len() < 33 {
        return None;
    }
    let (body, mac) = raw.split_at(raw.len() - 32);
    let mut h = HmacSha256::new_from_slice(MOCK_ATTEST_HMAC_SECRET).ok()?;
    h.update(body);
    let expected = h.finalize().into_bytes();
    if mac.ct_eq(&expected).unwrap_u8() == 0 {
        return None;
    }
    serde_json::from_slice(body).ok()
}
#[cfg(test)]
mod tests {
    use super::*;
    use ie_protocol::CpuTeeKind;
    use ie_protocol::WorkloadMeasurements;

    #[test]
    fn build_and_parse_mock_cpu_quote() {
        let payload = QuoteClaims {
            v: 1,
            kind: CpuTeeKind::SevSnp,
            ed25519_public: "pub".into(),
            tls_client_cert_sha256: String::new(),
            engine: WorkloadMeasurements {
                version: "1".into(),
                binary_sha256: "a".repeat(64),
            },
            vllm: WorkloadMeasurements {
                version: "1".into(),
                binary_sha256: "b".repeat(64),
            },
            ope: None,
            attested_mtls: None,
            issued_at: "2026-01-01T00:00:00Z".into(),
        };
        let quote = build_mock_cpu_quote(&payload);
        let parsed = parse_mock_cpu_quote(&quote).expect("parse");
        assert_eq!(parsed.ed25519_public, "pub");
    }
}
