//! Build production SEV-SNP AttestationBundle (port of `sev-snp/build-attestation.ts`).

use std::collections::HashMap;
use std::path::Path;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{SecondsFormat, Utc};
use ie_protocol::AttestationBundle;

use crate::claims::QuoteClaims;
use crate::error::AttestationError;
use crate::measurements::resolve_binary_measurements_from_env;
use crate::mock_quote::build_mock_cpu_quote;
use crate::nv_cc::{build_gpu_not_applicable_evidence, collect_nv_cc_gpu_evidence_b64};

use super::guest_report::{request_sev_snp_attestation_report, should_use_sev_snp_attestation};
use super::quote::{bind_report_data_64, encode_sev_snp_quote_wrapper, SevSnpQuoteWrapper};

fn env_flag_true(env: &HashMap<String, String>, key: &str) -> bool {
    env.get(key)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Mint the connect-time attestation bundle for live (or mock/stub) boots.
pub fn build_engine_attestation_bundle(
    env: &HashMap<String, String>,
    root: &Path,
    ed25519_public: &str,
    tls_client_cert_sha256: &str,
    nonce: Option<&str>,
) -> Result<AttestationBundle, AttestationError> {
    let measurements = resolve_binary_measurements_from_env(env, root)?;
    let issued_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let tls_hash = tls_client_cert_sha256.to_ascii_lowercase();
    let claims = QuoteClaims::from_measurements(ed25519_public, &tls_hash, &measurements, &issued_at);

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
        return Ok(claims.into_attestation_bundle(cpu_quote, gpu_evidence, &policy_id));
    }

    if env_flag_true(env, "TEECHAT_ENGINE_ALLOW_MOCK_ATTEST_ON_SNP") {
        let cpu_quote = build_mock_cpu_quote(&claims);
        let gpu_evidence = collect_nv_cc_gpu_evidence_b64(env, None)?;
        return Ok(claims.into_attestation_bundle(cpu_quote, gpu_evidence, &policy_id));
    }

    let report_data = bind_report_data_64(
        ed25519_public,
        &tls_hash,
        &measurements.engine_binary_sha256,
        &measurements.vllm_binary_sha256,
        &issued_at,
        nonce,
    );
    let report = request_sev_snp_attestation_report(&report_data, env)?;
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
    Ok(claims.into_attestation_bundle(cpu_quote, gpu_evidence, &policy_id))
}
