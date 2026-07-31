//! SEV-SNP quote wrapper v2 (port of `sev-snp/quote.ts`).

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;

use crate::claims::{QuoteClaims, QuoteEpochClaims};

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

/// REPORT_DATA that names an epoch's own keys (bind v2).
///
/// Byte-identical with `bindEpochReportData64` in
/// `TeaChat/vendor/inference-engine/src/sev-snp/quote.ts` and the client's
/// `epoch-evidence-browser.ts`. Changing the field order or the domain string
/// here silently invalidates every consumer, so all four move together.
pub fn bind_epoch_report_data_64(
    epoch: &QuoteEpochClaims,
    tls_client_cert_sha256: &str,
    engine_binary_sha256: &str,
    vllm_binary_sha256: &str,
    issued_at: &str,
    nonce: Option<&str>,
) -> [u8; 64] {
    let canonical = [
        "teechat-sev-snp-bind-v2",
        epoch.engine_id.as_str(),
        epoch.epoch_id.as_str(),
        epoch.not_before.as_str(),
        epoch.not_after.as_str(),
        epoch.mlkem_encapsulation_key.as_str(),
        epoch.x25519_public.as_str(),
        epoch.usage_signing_public.as_str(),
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
    let expected = match &wrapper.claims.epoch {
        Some(epoch) => bind_epoch_report_data_64(
            epoch,
            &wrapper.claims.tls_client_cert_sha256,
            &wrapper.claims.engine.binary_sha256,
            &wrapper.claims.vllm.binary_sha256,
            &wrapper.claims.issued_at,
            nonce,
        ),
        None => bind_report_data_64(
            &wrapper.claims.ed25519_public,
            &wrapper.claims.tls_client_cert_sha256,
            &wrapper.claims.engine.binary_sha256,
            &wrapper.claims.vllm.binary_sha256,
            &wrapper.claims.issued_at,
            nonce,
        ),
    };
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

    fn epoch_claims() -> QuoteEpochClaims {
        QuoteEpochClaims {
            engine_id: "engine-1".into(),
            epoch_id: "epoch-1".into(),
            not_before: "2026-07-31T00:00:00.000Z".into(),
            not_after: "2026-08-30T00:00:00.000Z".into(),
            mlkem_encapsulation_key: "bWxrZW0".into(),
            x25519_public: "eDI1NTE5".into(),
            usage_signing_public: "dXNhZ2U".into(),
        }
    }

    fn claims_with(epoch: Option<QuoteEpochClaims>) -> QuoteClaims {
        QuoteClaims {
            v: 1,
            kind: CpuTeeKind::SevSnp,
            ed25519_public: "pub".into(),
            tls_client_cert_sha256: "aa".repeat(32),
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
            launch_digest: None,
            epoch,
            issued_at: "2026-07-31T00:00:00.000Z".into(),
        }
    }

    fn wrapper_for(claims: QuoteClaims, nonce: Option<&str>) -> SevSnpQuoteWrapper {
        let data = match &claims.epoch {
            Some(epoch) => bind_epoch_report_data_64(
                epoch,
                &claims.tls_client_cert_sha256,
                &claims.engine.binary_sha256,
                &claims.vllm.binary_sha256,
                &claims.issued_at,
                nonce,
            ),
            None => bind_report_data_64(
                &claims.ed25519_public,
                &claims.tls_client_cert_sha256,
                &claims.engine.binary_sha256,
                &claims.vllm.binary_sha256,
                &claims.issued_at,
                nonce,
            ),
        };
        SevSnpQuoteWrapper {
            v: 2,
            kind: "sev-snp".into(),
            report_b64: "cm".into(),
            report_data_b64: STANDARD.encode(data),
            claims,
        }
    }

    #[test]
    fn bind_epoch_report_data_64_is_64_bytes_and_covers_every_epoch_field() {
        let base = epoch_claims();
        let baseline = bind_epoch_report_data_64(&base, "tls", "eng", "vllm", "ts", None).to_vec();
        assert_eq!(baseline.len(), 64);

        // Each field has to move the binding, or a swap in that field would go
        // unnoticed by a receiver comparing REPORT_DATA.
        let mutations: Vec<QuoteEpochClaims> = vec![
            QuoteEpochClaims {
                engine_id: "other".into(),
                ..base.clone()
            },
            QuoteEpochClaims {
                epoch_id: "other".into(),
                ..base.clone()
            },
            QuoteEpochClaims {
                not_before: "2020-01-01T00:00:00.000Z".into(),
                ..base.clone()
            },
            QuoteEpochClaims {
                not_after: "2020-01-01T00:00:00.000Z".into(),
                ..base.clone()
            },
            QuoteEpochClaims {
                mlkem_encapsulation_key: "other".into(),
                ..base.clone()
            },
            QuoteEpochClaims {
                x25519_public: "other".into(),
                ..base.clone()
            },
            QuoteEpochClaims {
                usage_signing_public: "other".into(),
                ..base.clone()
            },
        ];
        for mutated in mutations {
            let got =
                bind_epoch_report_data_64(&mutated, "tls", "eng", "vllm", "ts", None).to_vec();
            assert_ne!(got, baseline);
        }

        let with_nonce =
            bind_epoch_report_data_64(&base, "tls", "eng", "vllm", "ts", Some("n")).to_vec();
        assert_ne!(with_nonce, baseline);
    }

    #[test]
    fn bind_v1_and_v2_never_collide() {
        // Distinct domain strings keep connect-scoped evidence from ever being
        // accepted as evidence for an epoch.
        let epoch = epoch_claims();
        let v2 = bind_epoch_report_data_64(&epoch, "tls", "eng", "vllm", "ts", None);
        let v1 = bind_report_data_64("pub", "tls", "eng", "vllm", "ts", None);
        assert_ne!(v2.to_vec(), v1.to_vec());
    }

    #[test]
    fn verify_wrapper_report_data_picks_the_binding_the_claims_declare() {
        let with_epoch = wrapper_for(claims_with(Some(epoch_claims())), None);
        assert!(verify_wrapper_report_data(&with_epoch, None));

        let connect = wrapper_for(claims_with(None), None);
        assert!(verify_wrapper_report_data(&connect, None));
    }

    #[test]
    fn rejects_an_epoch_block_swapped_onto_another_epochs_report() {
        let mut wrapper = wrapper_for(claims_with(Some(epoch_claims())), None);
        wrapper.claims.epoch = Some(QuoteEpochClaims {
            x25519_public: "attacker-key".into(),
            ..epoch_claims()
        });
        assert!(!verify_wrapper_report_data(&wrapper, None));
    }

    #[test]
    fn rejects_connect_binding_presented_as_epoch_evidence() {
        // Report bound the boot identity; claims say it covers an epoch.
        let connect = wrapper_for(claims_with(None), None);
        let mut forged = connect.clone();
        forged.claims.epoch = Some(epoch_claims());
        assert!(!verify_wrapper_report_data(&forged, None));
    }

    #[test]
    fn epoch_binding_is_nonce_scoped() {
        let wrapper = wrapper_for(claims_with(Some(epoch_claims())), Some("challenge-1"));
        assert!(verify_wrapper_report_data(&wrapper, Some("challenge-1")));
        assert!(!verify_wrapper_report_data(&wrapper, Some("challenge-2")));
        assert!(!verify_wrapper_report_data(&wrapper, None));
    }

    #[test]
    fn epoch_claims_survive_the_wrapper_roundtrip() {
        let wrapper = wrapper_for(claims_with(Some(epoch_claims())), None);
        let encoded = encode_sev_snp_quote_wrapper(&wrapper);
        let parsed = parse_sev_snp_quote_wrapper(&encoded).expect("parse");
        assert_eq!(parsed.claims.epoch.as_ref(), Some(&epoch_claims()));
        assert!(verify_wrapper_report_data(&parsed, None));
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
                launch_digest: None,
                epoch: None,
                issued_at: "2026-01-01T00:00:00Z".into(),
            },
        };
        let encoded = encode_sev_snp_quote_wrapper(&wrapper);
        let parsed = parse_sev_snp_quote_wrapper(&encoded).expect("parse");
        assert_eq!(parsed.v, 2);
    }

    /// Guards the cross-runtime contract: the TS gateway, the browser client,
    /// and the OpenAPI edge all recompute this preimage. A change here that is
    /// not mirrored there silently rejects every epoch.
    #[test]
    fn bind_v2_preimage_matches_the_pinned_cross_runtime_vector() {
        let epoch = QuoteEpochClaims {
            engine_id: "engine-1".into(),
            epoch_id: "epoch-2026-07".into(),
            not_before: "2026-07-31T00:00:00.000Z".into(),
            not_after: "2026-08-30T00:00:00.000Z".into(),
            mlkem_encapsulation_key: "bWxrZW0".into(),
            x25519_public: "eDI1NTE5".into(),
            usage_signing_public: "dXNhZ2U".into(),
        };
        let got = bind_epoch_report_data_64(
            &epoch,
            &"aa".repeat(32),
            &"a".repeat(64),
            &"b".repeat(64),
            "2026-07-31T00:00:00.000Z",
            None,
        );
        let expected = {
            let canonical = [
                "teechat-sev-snp-bind-v2",
                "engine-1",
                "epoch-2026-07",
                "2026-07-31T00:00:00.000Z",
                "2026-08-30T00:00:00.000Z",
                "bWxrZW0",
                "eDI1NTE5",
                "dXNhZ2U",
                &"aa".repeat(32),
                &"a".repeat(64),
                &"b".repeat(64),
                "2026-07-31T00:00:00.000Z",
                "",
            ]
            .join("\0");
            Sha512::digest(canonical.as_bytes())
        };
        assert_eq!(got.to_vec(), expected[..64].to_vec());
    }
}
