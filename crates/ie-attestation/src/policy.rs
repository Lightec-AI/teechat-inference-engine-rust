//! Attestation policy verification (port of `attestation.ts` policy types).

use std::collections::HashSet;

use ie_protocol::AttestationBundle;

use crate::claims::QuoteClaims;
use crate::nv_cc::GpuAttestationPolicy;
use crate::verify::{CpuQuoteVerifier, VerifyError};

#[derive(Debug, Clone)]
pub struct AttestationPolicy {
    pub policy_id: String,
    pub allowed_engine_binary_sha256: HashSet<String>,
    pub allowed_vllm_binary_sha256: HashSet<String>,
    pub max_quote_age_ms: u64,
    pub gpu: GpuAttestationPolicy,
}

pub fn default_test_attestation_policy() -> AttestationPolicy {
    AttestationPolicy {
        policy_id: "teechat-cpu-tee-v1".into(),
        allowed_engine_binary_sha256: HashSet::from([(
            "a1b2c3d4e5f6789012345678abcdef9012345678abcdef9012345678abcdef90".into()
        )]),
        allowed_vllm_binary_sha256: HashSet::from([(
            "b2c3d4e5f6789012345678abcdef9012345678abcdef9012345678abcdef9012".into()
        )]),
        max_quote_age_ms: 24 * 60 * 60 * 1000,
        gpu: GpuAttestationPolicy {
            require_gpu_attestation: false,
            ..GpuAttestationPolicy::default()
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationVerifyResult {
    pub ok: bool,
    pub policy_id: String,
    pub reason: Option<String>,
}

pub fn verify_claims_against_policy(
    claims: &QuoteClaims,
    policy: &AttestationPolicy,
    now_ms: u64,
) -> AttestationVerifyResult {
    if !policy
        .allowed_engine_binary_sha256
        .contains(&claims.engine.binary_sha256)
    {
        return fail(&policy.policy_id, "engine_binary_not_allowed");
    }
    if !policy
        .allowed_vllm_binary_sha256
        .contains(&claims.vllm.binary_sha256)
    {
        return fail(&policy.policy_id, "vllm_binary_not_allowed");
    }
    if let Ok(issued) = chrono::DateTime::parse_from_rfc3339(&claims.issued_at) {
        let age = now_ms.saturating_sub(issued.timestamp_millis() as u64);
        if age > policy.max_quote_age_ms {
            return fail(&policy.policy_id, "quote_too_old");
        }
    }
    AttestationVerifyResult {
        ok: true,
        policy_id: policy.policy_id.clone(),
        reason: None,
    }
}

pub fn verify_bundle_with_verifier(
    bundle: &AttestationBundle,
    verifier: &dyn CpuQuoteVerifier,
    policy: &AttestationPolicy,
    now_ms: u64,
) -> Result<AttestationVerifyResult, VerifyError> {
    let claims = verifier.extract_claims(&bundle.cpu_tee.quote, bundle.cpu_tee.kind)?;
    let cpu = verify_claims_against_policy(&claims, policy, now_ms);
    if !cpu.ok {
        return Ok(cpu);
    }
    Ok(AttestationVerifyResult {
        ok: true,
        policy_id: policy.policy_id.clone(),
        reason: None,
    })
}

fn fail(policy_id: &str, reason: &str) -> AttestationVerifyResult {
    AttestationVerifyResult {
        ok: false,
        policy_id: policy_id.to_string(),
        reason: Some(reason.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ie_protocol::WorkloadMeasurements;

    #[test]
    fn verify_claims_against_policy_accepts_fixture_hashes() {
        let policy = default_test_attestation_policy();
        let claims = QuoteClaims {
            v: 1,
            kind: ie_protocol::CpuTeeKind::SevSnp,
            ed25519_public: "p".into(),
            tls_client_cert_sha256: String::new(),
            engine: WorkloadMeasurements {
                version: "f".into(),
                binary_sha256: "a1b2c3d4e5f6789012345678abcdef9012345678abcdef9012345678abcdef90"
                    .into(),
            },
            vllm: WorkloadMeasurements {
                version: "f".into(),
                binary_sha256: "b2c3d4e5f6789012345678abcdef9012345678abcdef9012345678abcdef9012"
                    .into(),
            },
            ope: None,
            attested_mtls: None,
            issued_at: chrono::Utc::now().to_rfc3339(),
        };
        let result = verify_claims_against_policy(&claims, &policy, chrono::Utc::now().timestamp_millis() as u64);
        assert!(result.ok);
    }
}
