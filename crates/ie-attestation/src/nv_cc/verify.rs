//! Validate nvattest claims against TeeChat GPU policy.

use std::collections::HashMap;

use super::policy::{GpuAttestationPolicy, GpuEvidenceVerifyResult};

fn claim_bool(claims: &Map, key: &str) -> bool {
    claims.get(key).and_then(|v| v.as_bool()) == Some(true)
}

type Map = HashMap<String, serde_json::Value>;

fn cert_chain_validated(claims: &Map) -> bool {
    if claim_bool(claims, "x-nvidia-gpu-attestation-report-cert-chain-validated") {
        return true;
    }
    let Some(chain) = claims.get("x-nvidia-gpu-attestation-report-cert-chain") else {
        return false;
    };
    chain.get("x-nvidia-cert-status").and_then(|v| v.as_str()) == Some("valid")
        && chain.get("x-nvidia-cert-ocsp-status").and_then(|v| v.as_str()) == Some("good")
}

fn rim_schema_validated(claims: &Map, kind: &str) -> bool {
    let flat = match kind {
        "driver" => "x-nvidia-gpu-driver-rim-schema-validated",
        _ => "x-nvidia-gpu-vbios-rim-schema-validated",
    };
    if claim_bool(claims, flat) {
        return true;
    }
    let (sig, ver) = match kind {
        "driver" => (
            "x-nvidia-gpu-driver-rim-signature-verified",
            "x-nvidia-gpu-driver-rim-version-match",
        ),
        _ => (
            "x-nvidia-gpu-vbios-rim-signature-verified",
            "x-nvidia-gpu-vbios-rim-version-match",
        ),
    };
    claim_bool(claims, sig) && claim_bool(claims, ver)
}

fn claim_required_true(claims: &Map, key: &str) -> bool {
    match key {
        "x-nvidia-gpu-attestation-report-cert-chain-validated" => cert_chain_validated(claims),
        "x-nvidia-gpu-driver-rim-schema-validated" => rim_schema_validated(claims, "driver"),
        "x-nvidia-gpu-vbios-rim-schema-validated" => rim_schema_validated(claims, "vbios"),
        other => claim_bool(claims, other),
    }
}

pub fn validate_nv_gpu_claims_against_policy(
    claims: &Map,
    policy: &GpuAttestationPolicy,
) -> GpuEvidenceVerifyResult {
    for key in [
        "x-nvidia-gpu-driver-rim-signature-verified",
        "x-nvidia-gpu-vbios-rim-signature-verified",
        "x-nvidia-gpu-attestation-report-cert-chain-validated",
        "x-nvidia-gpu-attestation-report-signature-verified",
        "x-nvidia-gpu-driver-rim-schema-validated",
        "x-nvidia-gpu-vbios-rim-schema-validated",
        "x-nvidia-gpu-arch-check",
    ] {
        if !claim_required_true(claims, key) {
            return fail(&format!("gpu_claim_{key}"));
        }
    }
    if claims.get("measres").and_then(|v| v.as_str()) != Some("success") {
        return fail("gpu_measres_not_success");
    }
    if claims.get("secboot").and_then(|v| v.as_bool()) != Some(true) {
        return fail("gpu_secboot_false");
    }
    let driver = claims
        .get("x-nvidia-gpu-driver-version")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if !policy.allowed_gpu_driver_versions.is_empty()
        && !policy.allowed_gpu_driver_versions.contains(&driver)
    {
        return fail("gpu_driver_version_not_allowed");
    }
    let vbios = claims
        .get("x-nvidia-gpu-vbios-version")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if !policy.allowed_gpu_vbios_versions.is_empty()
        && !policy.allowed_gpu_vbios_versions.contains(&vbios)
    {
        return fail("gpu_vbios_version_not_allowed");
    }
    if !policy.allowed_gpu_architectures.is_empty() {
        let arch = claims
            .get("x-nvidia-gpu-architecture")
            .or_else(|| claims.get("arch"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_ascii_uppercase();
        let allowed: Vec<String> = policy
            .allowed_gpu_architectures
            .iter()
            .map(|a| a.trim().to_ascii_uppercase())
            .collect();
        if !allowed.iter().any(|a| a == &arch) {
            return fail("gpu_architecture_not_allowed");
        }
    }
    GpuEvidenceVerifyResult {
        ok: true,
        reason: None,
    }
}

pub fn verify_nv_cc_gpu_evidence(
    evidence_b64: &str,
    policy: &GpuAttestationPolicy,
    skip_gpu_verification: bool,
    production_build: bool,
) -> GpuEvidenceVerifyResult {
    if (evidence_b64.contains("gpu-tee-pending") || evidence_b64 == "Z3B1LXRlZS1wZW5kaW5n")
        && production_build
    {
        return fail("legacy_gpu_placeholder");
    }
    let Ok(raw) = ope_crypto::decode(evidence_b64) else {
        return fail("decode_failed");
    };
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&raw) else {
        return fail("invalid_json");
    };
    if v.get("not_applicable").and_then(|b| b.as_bool()) == Some(true) && skip_gpu_verification {
        return GpuEvidenceVerifyResult {
            ok: true,
            reason: None,
        };
    }
    if v.get("source").and_then(|s| s.as_str()) == Some("mock") {
        return super::mock::verify_mock_nv_cc_gpu_evidence(evidence_b64);
    }
    if policy.require_gpu_attestation {
        fail("gpu_evidence_not_verified")
    } else {
        GpuEvidenceVerifyResult {
            ok: true,
            reason: None,
        }
    }
}

fn fail(reason: &str) -> GpuEvidenceVerifyResult {
    GpuEvidenceVerifyResult {
        ok: false,
        reason: Some(reason.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::default_gpu_attestation_policy;
    use std::collections::HashSet;

    fn passing_claims() -> Map {
        Map::from([
            ("x-nvidia-gpu-driver-rim-signature-verified".into(), true.into()),
            ("x-nvidia-gpu-vbios-rim-signature-verified".into(), true.into()),
            (
                "x-nvidia-gpu-attestation-report-cert-chain-validated".into(),
                true.into(),
            ),
            (
                "x-nvidia-gpu-attestation-report-signature-verified".into(),
                true.into(),
            ),
            ("x-nvidia-gpu-driver-rim-schema-validated".into(), true.into()),
            ("x-nvidia-gpu-vbios-rim-schema-validated".into(), true.into()),
            ("x-nvidia-gpu-arch-check".into(), true.into()),
            ("measres".into(), "success".into()),
            ("secboot".into(), true.into()),
            ("x-nvidia-gpu-driver-version".into(), "580.95.05".into()),
            ("x-nvidia-gpu-vbios-version".into(), "97.00.88.00.0F".into()),
            ("x-nvidia-gpu-architecture".into(), "BLACKWELL".into()),
        ])
    }

    #[test]
    fn validate_nv_gpu_claims_against_policy_passes() {
        let mut policy = default_gpu_attestation_policy();
        policy.allowed_gpu_architectures = HashSet::from(["blackwell".into()]);
        let verdict = validate_nv_gpu_claims_against_policy(&passing_claims(), &policy);
        assert!(verdict.ok);
    }

    #[test]
    fn validate_nv_gpu_claims_rejects_driver_version() {
        let mut policy = default_gpu_attestation_policy();
        policy.allowed_gpu_driver_versions = HashSet::from(["575.32".into()]);
        let verdict = validate_nv_gpu_claims_against_policy(&passing_claims(), &policy);
        assert!(!verdict.ok);
        assert_eq!(verdict.reason.as_deref(), Some("gpu_driver_version_not_allowed"));
    }
}
