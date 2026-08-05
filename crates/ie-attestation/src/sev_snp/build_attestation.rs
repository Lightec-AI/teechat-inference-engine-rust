//! Build production SEV-SNP AttestationBundle (port of `sev-snp/build-attestation.ts`).

use std::collections::HashMap;
use std::path::Path;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{SecondsFormat, Utc};
use ie_protocol::AttestationBundle;

use crate::claims::{QuoteClaims, QuoteEpochClaims};
use crate::error::AttestationError;
use crate::measurements::resolve_binary_measurements_from_env;
use crate::mock_quote::build_mock_cpu_quote;
use crate::nv_cc::{build_gpu_not_applicable_evidence, collect_nv_cc_gpu_evidence_b64};

use super::endorsement::load_cpu_tee_endorsement_from_env;
use super::guest_report::{request_sev_snp_attestation_report, should_use_sev_snp_attestation};
use super::launch_digest::launch_digest_from_report;
use super::quote::{
    bind_epoch_report_data_64, bind_report_data_64, encode_sev_snp_quote_wrapper,
    SevSnpQuoteWrapper,
};

fn env_flag_true(env: &HashMap<String, String>, key: &str) -> bool {
    env.get(key)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn with_cpu_endorsement(
    mut bundle: AttestationBundle,
    env: &HashMap<String, String>,
) -> AttestationBundle {
    bundle.cpu_tee.endorsement = load_cpu_tee_endorsement_from_env(env);
    bundle
}

/// Mint the connect-time attestation bundle for live (or mock/stub) boots.
pub fn build_engine_attestation_bundle(
    env: &HashMap<String, String>,
    root: &Path,
    ed25519_public: &str,
    tls_client_cert_sha256: &str,
    nonce: Option<&str>,
) -> Result<AttestationBundle, AttestationError> {
    build_bundle(
        env,
        root,
        ed25519_public,
        tls_client_cert_sha256,
        nonce,
        None,
    )
}

/// Mint evidence over an epoch's own key material (bind v2).
///
/// Each rotation gets its own hardware report. Reusing the boot bundle would
/// leave the epoch keys vouched for only by the boot identity's signature,
/// which is the gap this closes (RB-45).
pub fn build_engine_epoch_attestation_bundle(
    env: &HashMap<String, String>,
    root: &Path,
    ed25519_public: &str,
    tls_client_cert_sha256: &str,
    epoch: &QuoteEpochClaims,
    nonce: Option<&str>,
) -> Result<AttestationBundle, AttestationError> {
    build_bundle(
        env,
        root,
        ed25519_public,
        tls_client_cert_sha256,
        nonce,
        Some(epoch),
    )
}

fn build_bundle(
    env: &HashMap<String, String>,
    root: &Path,
    ed25519_public: &str,
    tls_client_cert_sha256: &str,
    nonce: Option<&str>,
    epoch: Option<&QuoteEpochClaims>,
) -> Result<AttestationBundle, AttestationError> {
    let measurements = resolve_binary_measurements_from_env(env, root)?;
    let issued_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let tls_hash = tls_client_cert_sha256.to_ascii_lowercase();
    let mut claims =
        QuoteClaims::from_measurements(ed25519_public, &tls_hash, &measurements, &issued_at);
    claims.epoch = epoch.cloned();
    // Dev/CI override only — production path fills from SNP report MEASUREMENT below.
    if let Some(ld) = env.get("TEECHAT_LAUNCH_DIGEST") {
        let t = ld.trim().to_ascii_lowercase();
        if t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit()) {
            claims.launch_digest = Some(t);
        }
    }

    let policy_id = env
        .get("TEECHAT_ATTESTATION_POLICY_ID")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("teechat-cpu-tee-prod-v1")
        .to_string();

    if !should_use_sev_snp_attestation(env) {
        let cpu_quote = build_mock_cpu_quote(&claims);
        let gpu_evidence = if env_flag_true(env, "TEECHAT_ENGINE_STUB") {
            build_gpu_not_applicable_evidence()
        } else {
            collect_nv_cc_gpu_evidence_b64(env, None)?
        };
        return Ok(with_cpu_endorsement(
            claims.into_attestation_bundle(cpu_quote, gpu_evidence, &policy_id),
            env,
        ));
    }

    if env_flag_true(env, "TEECHAT_ENGINE_ALLOW_MOCK_ATTEST_ON_SNP") {
        let cpu_quote = build_mock_cpu_quote(&claims);
        let gpu_evidence = collect_nv_cc_gpu_evidence_b64(env, None)?;
        return Ok(with_cpu_endorsement(
            claims.into_attestation_bundle(cpu_quote, gpu_evidence, &policy_id),
            env,
        ));
    }

    let report_data = match epoch {
        Some(epoch) => bind_epoch_report_data_64(
            epoch,
            &tls_hash,
            &measurements.engine_binary_sha256,
            &measurements.vllm_binary_sha256,
            &issued_at,
            nonce,
        ),
        None => bind_report_data_64(
            ed25519_public,
            &tls_hash,
            &measurements.engine_binary_sha256,
            &measurements.vllm_binary_sha256,
            &issued_at,
            nonce,
        ),
    };
    let report = request_sev_snp_attestation_report(&report_data, env)?;
    if let Some(ld) = launch_digest_from_report(&report) {
        claims.launch_digest = Some(ld);
    }
    let gpu_nonce = hex::encode(&report_data[..32]);
    let gpu_evidence = collect_nv_cc_gpu_evidence_b64(env, Some(&gpu_nonce))?;

    let wrapper = SevSnpQuoteWrapper {
        v: 2,
        kind: "sev-snp".into(),
        report_b64: STANDARD.encode(&report),
        report_data_b64: STANDARD.encode(report_data),
        claims: claims.clone(),
    };
    let cpu_quote = encode_sev_snp_quote_wrapper(&wrapper);
    Ok(with_cpu_endorsement(
        claims.into_attestation_bundle(cpu_quote, gpu_evidence, &policy_id),
        env,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::QuoteEpochClaims;
    use crate::epoch_evidence::{match_epoch_evidence, EpochEvidenceError, EpochEvidenceSubject};
    use crate::mock_quote::parse_mock_cpu_quote;
    use ie_protocol::EngineHybridPublic;
    use tempfile::TempDir;

    fn stub_env() -> HashMap<String, String> {
        HashMap::from([
            ("TEECHAT_ENGINE_STUB".into(), "1".into()),
            (
                "TEECHAT_IE_RUNTIME_SHA256".into(),
                "a1b2c3d4e5f6789012345678abcdef9012345678abcdef9012345678abcdef90".into(),
            ),
            (
                "TEECHAT_VLLM_BINARY_SHA256".into(),
                "b2c3d4e5f6789012345678abcdef9012345678abcdef9012345678abcdef9012".into(),
            ),
        ])
    }

    fn epoch_claims(epoch_id: &str) -> QuoteEpochClaims {
        QuoteEpochClaims {
            engine_id: "engine-1".into(),
            epoch_id: epoch_id.into(),
            not_before: "2026-07-31T00:00:00.000Z".into(),
            not_after: "2026-08-30T00:00:00.000Z".into(),
            mlkem_encapsulation_key: "bWxrZW0".into(),
            x25519_public: "eDI1NTE5".into(),
            usage_signing_public: "dXNhZ2U".into(),
        }
    }

    fn hybrid() -> EngineHybridPublic {
        EngineHybridPublic {
            kex: "X25519MLKEM768".into(),
            mlkem_encapsulation_key: "bWxrZW0".into(),
            x25519_public: "eDI1NTE5".into(),
        }
    }

    fn subject<'a>(e: &'a QuoteEpochClaims, h: &'a EngineHybridPublic) -> EpochEvidenceSubject<'a> {
        EpochEvidenceSubject {
            engine_id: &e.engine_id,
            epoch_id: &e.epoch_id,
            not_before: &e.not_before,
            not_after: &e.not_after,
            hybrid: h,
        }
    }

    #[test]
    fn epoch_bundle_carries_evidence_a_receiver_accepts() {
        let dir = TempDir::new().unwrap();
        let epoch = epoch_claims("epoch-a");
        let bundle = build_engine_epoch_attestation_bundle(
            &stub_env(),
            dir.path(),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            &"0".repeat(64),
            &epoch,
            None,
        )
        .expect("bundle");

        let claims = parse_mock_cpu_quote(&bundle.cpu_tee.quote).expect("claims");
        let h = hybrid();
        assert!(match_epoch_evidence(&claims, &subject(&epoch, &h)).is_ok());
    }

    #[test]
    fn evidence_for_one_epoch_does_not_authorize_another() {
        let dir = TempDir::new().unwrap();
        let bundle = build_engine_epoch_attestation_bundle(
            &stub_env(),
            dir.path(),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            &"0".repeat(64),
            &epoch_claims("epoch-a"),
            None,
        )
        .expect("bundle");

        let claims = parse_mock_cpu_quote(&bundle.cpu_tee.quote).expect("claims");
        let other = epoch_claims("epoch-b");
        let h = hybrid();
        assert_eq!(
            match_epoch_evidence(&claims, &subject(&other, &h)).unwrap_err(),
            EpochEvidenceError::EpochMismatch
        );
    }

    #[test]
    fn connect_bundle_carries_no_epoch_block() {
        let dir = TempDir::new().unwrap();
        let bundle = build_engine_attestation_bundle(
            &stub_env(),
            dir.path(),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            &"0".repeat(64),
            None,
        )
        .expect("bundle");

        let claims = parse_mock_cpu_quote(&bundle.cpu_tee.quote).expect("claims");
        let e = epoch_claims("epoch-a");
        let h = hybrid();
        assert_eq!(
            match_epoch_evidence(&claims, &subject(&e, &h)).unwrap_err(),
            EpochEvidenceError::Absent
        );
    }

    #[test]
    fn connect_bundle_attaches_configured_cpu_endorsement() {
        let dir = TempDir::new().unwrap();
        let mut env = stub_env();
        env.insert("TEECHAT_SNP_VCEK_DER_B64".into(), "dnNlaw==".into());
        env.insert("TEECHAT_SNP_ASK_DER_B64".into(), "YXNr".into());
        let bundle = build_engine_attestation_bundle(
            &env,
            dir.path(),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            &"0".repeat(64),
            None,
        )
        .expect("bundle");

        let endorsement = bundle.cpu_tee.endorsement.expect("endorsement");
        assert_eq!(endorsement.vcek_der_b64, "dnNlaw==");
        assert_eq!(endorsement.ask_der_b64.as_deref(), Some("YXNr"));
    }
}
