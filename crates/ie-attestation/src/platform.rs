//! Gateway platform attestation verify at engine connect (SEC-029 / `verifyPlatformAttestationBundle`).

use std::collections::HashSet;

use ie_protocol::AttestationBundle;

use crate::fixture::MockCpuQuoteVerifier;
use crate::policy::{
    verify_bundle_with_verifier, AttestationPolicy, AttestationVerifyResult,
};
use crate::verify::CpuQuoteVerifier;

/// Platform-side allowlists for gateway + skill-hub binaries (SEC-029).
#[derive(Debug, Clone)]
pub struct PlatformAttestationPolicy {
    pub policy_id: String,
    pub allowed_gateway_binary_sha256: HashSet<String>,
    pub allowed_skill_hub_binary_sha256: HashSet<String>,
    pub max_quote_age_ms: u64,
}

/// Binding values expected in the gateway's returned attestation bundle.
#[derive(Debug, Clone)]
pub struct PlatformAttestationBind {
    pub gateway_binary_sha256: String,
    pub skill_hub_binary_sha256: String,
    pub ed25519_public: String,
}

fn fail(policy_id: &str, reason: &str) -> AttestationVerifyResult {
    AttestationVerifyResult {
        ok: false,
        policy_id: policy_id.to_string(),
        reason: Some(reason.to_string()),
    }
}

/// Verify gateway platform attestation returned at engine connect (SEC-029).
pub fn verify_platform_attestation_bundle(
    bundle: &AttestationBundle,
    engine_policy: &AttestationPolicy,
    platform_policy: &PlatformAttestationPolicy,
    bind: &PlatformAttestationBind,
    now_ms: u64,
    verifier: &dyn CpuQuoteVerifier,
) -> AttestationVerifyResult {
    let gw = bind.gateway_binary_sha256.trim().to_ascii_lowercase();
    let sh = bind.skill_hub_binary_sha256.trim().to_ascii_lowercase();

    if !platform_policy.allowed_gateway_binary_sha256.is_empty()
        && !platform_policy.allowed_gateway_binary_sha256.contains(&gw)
    {
        return fail(&platform_policy.policy_id, "gateway_hash_not_allowed");
    }
    if !platform_policy.allowed_skill_hub_binary_sha256.is_empty()
        && !platform_policy.allowed_skill_hub_binary_sha256.contains(&sh)
    {
        return fail(&platform_policy.policy_id, "skill_hub_hash_not_allowed");
    }

    let mut quote_policy = engine_policy.clone();
    quote_policy
        .allowed_engine_binary_sha256
        .insert(gw.clone());
    quote_policy.allowed_vllm_binary_sha256.insert(sh.clone());
    if quote_policy.max_quote_age_ms == 0 {
        quote_policy.max_quote_age_ms = platform_policy.max_quote_age_ms;
    }

    let verdict = match verify_bundle_with_verifier(bundle, verifier, &quote_policy, now_ms) {
        Ok(v) => v,
        Err(_) => return fail(&platform_policy.policy_id, "quote_unverifiable"),
    };
    if !verdict.ok {
        return verdict;
    }

    if bundle.engine.binary_sha256.to_ascii_lowercase() != gw {
        return fail(&platform_policy.policy_id, "gateway_hash_bundle_mismatch");
    }
    if bundle.vllm.binary_sha256.to_ascii_lowercase() != sh {
        return fail(&platform_policy.policy_id, "skill_hub_hash_bundle_mismatch");
    }

    // ed25519 binding: mock/SNP claims must match expected gateway public key when extractable.
    if let Ok(claims) = verifier.extract_claims(&bundle.cpu_tee.quote, bundle.cpu_tee.kind) {
        let expected = bind.ed25519_public.trim();
        if !expected.is_empty() && claims.ed25519_public.trim() != expected {
            return fail(&platform_policy.policy_id, "ed25519_mismatch");
        }
    }

    AttestationVerifyResult {
        ok: true,
        policy_id: platform_policy.policy_id.clone(),
        reason: None,
    }
}

/// Convenience: verify with [`MockCpuQuoteVerifier`] (mock quotes + fixture backends).
pub fn verify_platform_attestation_bundle_mock(
    bundle: &AttestationBundle,
    engine_policy: &AttestationPolicy,
    platform_policy: &PlatformAttestationPolicy,
    bind: &PlatformAttestationBind,
    now_ms: u64,
) -> AttestationVerifyResult {
    verify_platform_attestation_bundle(
        bundle,
        engine_policy,
        platform_policy,
        bind,
        now_ms,
        &MockCpuQuoteVerifier,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::QuoteClaims;
    use crate::mock_quote::build_mock_cpu_quote;
    use crate::policy::default_test_attestation_policy;
    use ie_protocol::{
        AttestationVerdict, CpuTeeAttestation, CpuTeeKind, GpuTeeAttestation, GpuTeeKind,
        WorkloadMeasurements,
    };

    fn gw_hash() -> String {
        "c3d4e5f6789012345678abcdef9012345678abcdef9012345678abcdef901234".into()
    }
    fn sh_hash() -> String {
        "d4e5f6789012345678abcdef9012345678abcdef9012345678abcdef90123456".into()
    }

    fn sample_gateway_bundle(ed25519: &str) -> AttestationBundle {
        let claims = QuoteClaims {
            v: 1,
            kind: CpuTeeKind::SevSnp,
            ed25519_public: ed25519.into(),
            tls_client_cert_sha256: String::new(),
            engine: WorkloadMeasurements {
                version: "gw".into(),
                binary_sha256: gw_hash(),
            },
            vllm: WorkloadMeasurements {
                version: "sh".into(),
                binary_sha256: sh_hash(),
            },
            ope: None,
            attested_mtls: None,
            issued_at: chrono::Utc::now().to_rfc3339(),
        };
        let quote = build_mock_cpu_quote(&claims);
        AttestationBundle {
            cpu_tee: CpuTeeAttestation {
                kind: CpuTeeKind::SevSnp,
                quote,
                verdict: AttestationVerdict::Pass,
                policy_id: "p".into(),
            },
            gpu_tee: GpuTeeAttestation {
                kind: GpuTeeKind::NvCc,
                evidence: String::new(),
                verdict: AttestationVerdict::Pass,
            },
            vllm: claims.vllm,
            engine: claims.engine,
            ope: None,
            attested_mtls: None,
        }
    }

    #[test]
    fn platform_verify_ok() {
        let ed = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let bundle = sample_gateway_bundle(ed);
        let engine_policy = default_test_attestation_policy();
        let platform = PlatformAttestationPolicy {
            policy_id: "plat".into(),
            allowed_gateway_binary_sha256: HashSet::from([gw_hash()]),
            allowed_skill_hub_binary_sha256: HashSet::from([sh_hash()]),
            max_quote_age_ms: 86_400_000,
        };
        let bind = PlatformAttestationBind {
            gateway_binary_sha256: gw_hash(),
            skill_hub_binary_sha256: sh_hash(),
            ed25519_public: ed.into(),
        };
        let now = chrono::Utc::now().timestamp_millis() as u64;
        let v = verify_platform_attestation_bundle_mock(
            &bundle,
            &engine_policy,
            &platform,
            &bind,
            now,
        );
        assert!(v.ok, "{v:?}");
    }

    #[test]
    fn platform_verify_rejects_hash_mismatch() {
        let ed = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let bundle = sample_gateway_bundle(ed);
        let engine_policy = default_test_attestation_policy();
        let platform = PlatformAttestationPolicy {
            policy_id: "plat".into(),
            allowed_gateway_binary_sha256: HashSet::from([gw_hash()]),
            allowed_skill_hub_binary_sha256: HashSet::from([sh_hash()]),
            max_quote_age_ms: 86_400_000,
        };
        let bind = PlatformAttestationBind {
            gateway_binary_sha256: "ff".repeat(32),
            skill_hub_binary_sha256: sh_hash(),
            ed25519_public: ed.into(),
        };
        let now = chrono::Utc::now().timestamp_millis() as u64;
        let v = verify_platform_attestation_bundle_mock(
            &bundle,
            &engine_policy,
            &platform,
            &bind,
            now,
        );
        assert!(!v.ok);
        assert_eq!(v.reason.as_deref(), Some("gateway_hash_not_allowed"));
    }
}
