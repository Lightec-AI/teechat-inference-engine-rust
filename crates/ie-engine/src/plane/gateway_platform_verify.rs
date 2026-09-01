//! Engine-side mutual gateway platform verify at attested connect (SEC-029).
//! Port of `runtime/engine-gateway-platform-verify.ts`.

use std::collections::{HashMap, HashSet};

use ie_attestation::{
    default_test_attestation_policy, load_attestation_policy_from_file, AttestationPolicy,
    PlatformAttestationBind, PlatformAttestationPolicy, PolicyFileError,
};

use super::verify::PlatformPolicyGatewayAttestationVerifier;

fn env_trim<'a>(env: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    env.get(key).map(|s| s.trim()).filter(|s| !s.is_empty())
}

fn split_hashes(raw: &str) -> HashSet<String> {
    raw.split(|c: char| c.is_whitespace() || c == ',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

struct ResolvedEnginePolicy {
    engine_policy: AttestationPolicy,
    file_gateway_hashes: Option<HashSet<String>>,
    file_skill_hub_hashes: Option<HashSet<String>>,
}

fn apply_env_overlays(env: &HashMap<String, String>, policy: &mut AttestationPolicy) {
    if let Some(id) = env_trim(env, "TEECHAT_ATTESTATION_POLICY_ID") {
        policy.policy_id = id.to_string();
    }
    if let Some(ms) =
        env_trim(env, "TEECHAT_ATTESTATION_MAX_QUOTE_AGE_MS").and_then(|s| s.parse().ok())
    {
        policy.max_quote_age_ms = ms;
    }
}

/// Load signed allowlists when `TEECHAT_ATTESTATION_POLICY_PATH` is set.
/// Missing file or empty required allowlists fail closed (no test-policy fallback).
fn resolve_engine_policy(
    env: &HashMap<String, String>,
) -> Result<ResolvedEnginePolicy, PolicyFileError> {
    if let Some(path) = env_trim(env, "TEECHAT_ATTESTATION_POLICY_PATH") {
        let loaded = load_attestation_policy_from_file(path)?;
        let mut engine_policy = loaded.engine_policy;
        apply_env_overlays(env, &mut engine_policy);
        return Ok(ResolvedEnginePolicy {
            engine_policy,
            file_gateway_hashes: Some(loaded.allowed_gateway_binary_sha256),
            file_skill_hub_hashes: Some(loaded.allowed_skill_hub_binary_sha256),
        });
    }
    let mut engine_policy = default_test_attestation_policy();
    apply_env_overlays(env, &mut engine_policy);
    Ok(ResolvedEnginePolicy {
        engine_policy,
        file_gateway_hashes: None,
        file_skill_hub_hashes: None,
    })
}

/// Build SEC-029 platform verifier from TeeChat env keys (default ON when called).
///
/// When `TEECHAT_ATTESTATION_POLICY_PATH` is set, gateway allowlists come from that
/// file (fail-closed). Env `TEECHAT_ALLOWED_GATEWAY_BINARY_SHA256` is ignored in
/// that case so a stale env pin cannot widen the signed set.
pub fn platform_policy_verifier_from_env(
    env: &HashMap<String, String>,
) -> Result<PlatformPolicyGatewayAttestationVerifier, PolicyFileError> {
    let resolved = resolve_engine_policy(env)?;
    let gateway_binary_sha256 = env_trim(env, "TEECHAT_GATEWAY_BINARY_SHA256")
        .unwrap_or("c3d4e5f6789012345678abcdef9012345678abcdef9012345678abcdef901234")
        .to_ascii_lowercase();
    let skill_hub_binary_sha256 = env_trim(env, "TEECHAT_SKILL_HUB_BINARY_SHA256")
        .unwrap_or(gateway_binary_sha256.as_str())
        .to_ascii_lowercase();
    let gateway_ed25519_public = env_trim(env, "TEECHAT_GATEWAY_ED25519_PUBLIC")
        .unwrap_or("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        .to_string();

    let allowed_gw = match resolved.file_gateway_hashes {
        Some(file) => file,
        None => env_trim(env, "TEECHAT_ALLOWED_GATEWAY_BINARY_SHA256")
            .map(split_hashes)
            .unwrap_or_else(|| HashSet::from([gateway_binary_sha256.clone()])),
    };
    let allowed_sh = match resolved.file_skill_hub_hashes {
        Some(file) => file,
        None => env_trim(env, "TEECHAT_ALLOWED_SKILL_HUB_BINARY_SHA256")
            .map(split_hashes)
            .unwrap_or_else(|| HashSet::from([skill_hub_binary_sha256.clone()])),
    };

    let platform_policy = PlatformAttestationPolicy {
        policy_id: resolved.engine_policy.policy_id.clone(),
        allowed_gateway_binary_sha256: allowed_gw,
        allowed_skill_hub_binary_sha256: allowed_sh,
        max_quote_age_ms: resolved.engine_policy.max_quote_age_ms,
    };

    Ok(PlatformPolicyGatewayAttestationVerifier {
        engine_policy: resolved.engine_policy,
        platform_policy,
        bind: PlatformAttestationBind {
            gateway_binary_sha256,
            skill_hub_binary_sha256,
            ed25519_public: gateway_ed25519_public,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN_JSON: &str = r#"{
      "policyId": "teechat-cpu-tee-prod-v1",
      "allowedEngineBinarySha256": ["aa11111111111111111111111111111111111111111111111111111111111111"],
      "allowedVllmBinarySha256": ["bb22222222222222222222222222222222222222222222222222222222222222"],
      "allowedGatewayBinarySha256": ["cc33333333333333333333333333333333333333333333333333333333333333"],
      "maxQuoteAgeMs": 86400000
    }"#;

    #[test]
    fn builds_verifier_with_defaults() {
        let env = HashMap::new();
        let v = platform_policy_verifier_from_env(&env).expect("defaults");
        assert!(!v.bind.gateway_binary_sha256.is_empty());
        assert!(v
            .platform_policy
            .allowed_gateway_binary_sha256
            .contains(&v.bind.gateway_binary_sha256));
    }

    #[test]
    fn loads_policy_file_and_uses_gateway_allowlist() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.json");
        std::fs::write(&path, MIN_JSON).unwrap();
        let env = HashMap::from([
            (
                "TEECHAT_ATTESTATION_POLICY_PATH".into(),
                path.to_string_lossy().into_owned(),
            ),
            (
                "TEECHAT_GATEWAY_BINARY_SHA256".into(),
                "cc33333333333333333333333333333333333333333333333333333333333333".into(),
            ),
            (
                "TEECHAT_ALLOWED_GATEWAY_BINARY_SHA256".into(),
                "dd44444444444444444444444444444444444444444444444444444444444444".into(),
            ),
        ]);
        let v = platform_policy_verifier_from_env(&env).expect("file");
        assert_eq!(v.engine_policy.policy_id, "teechat-cpu-tee-prod-v1");
        assert!(v
            .engine_policy
            .allowed_engine_binary_sha256
            .contains("aa11111111111111111111111111111111111111111111111111111111111111"));
        assert!(v
            .platform_policy
            .allowed_gateway_binary_sha256
            .contains("cc33333333333333333333333333333333333333333333333333333333333333"));
        assert!(
            !v.platform_policy
                .allowed_gateway_binary_sha256
                .contains("dd44444444444444444444444444444444444444444444444444444444444444"),
            "env must not widen the signed gateway allowlist"
        );
    }

    #[test]
    fn missing_policy_file_fails_closed() {
        let env = HashMap::from([(
            "TEECHAT_ATTESTATION_POLICY_PATH".into(),
            "/no/such/attestation-policy.json".into(),
        )]);
        match platform_policy_verifier_from_env(&env) {
            Ok(_) => panic!("missing policy file must fail closed"),
            Err(err) => assert!(matches!(err, PolicyFileError::Missing { .. })),
        }
    }
}
