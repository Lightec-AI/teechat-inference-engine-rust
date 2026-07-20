//! Engine-side mutual gateway platform verify at attested connect (SEC-029).
//! Port of `runtime/engine-gateway-platform-verify.ts`.

use std::collections::{HashMap, HashSet};

use ie_attestation::{
    default_test_attestation_policy, AttestationPolicy, PlatformAttestationBind,
    PlatformAttestationPolicy,
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

fn resolve_engine_policy(env: &HashMap<String, String>) -> AttestationPolicy {
    // File-based policy load is optional; fall back to test/default allowlists.
    let _ = env_trim(env, "TEECHAT_ATTESTATION_POLICY_PATH");
    let mut policy = default_test_attestation_policy();
    if let Some(id) = env_trim(env, "TEECHAT_ATTESTATION_POLICY_ID") {
        policy.policy_id = id.to_string();
    }
    if let Some(ms) = env_trim(env, "TEECHAT_ATTESTATION_MAX_QUOTE_AGE_MS")
        .and_then(|s| s.parse().ok())
    {
        policy.max_quote_age_ms = ms;
    }
    policy
}

/// Build SEC-029 platform verifier from TeeChat env keys (default ON when called).
pub fn platform_policy_verifier_from_env(
    env: &HashMap<String, String>,
) -> PlatformPolicyGatewayAttestationVerifier {
    let engine_policy = resolve_engine_policy(env);
    let gateway_binary_sha256 = env_trim(env, "TEECHAT_GATEWAY_BINARY_SHA256")
        .unwrap_or("c3d4e5f6789012345678abcdef9012345678abcdef9012345678abcdef901234")
        .to_ascii_lowercase();
    let skill_hub_binary_sha256 = env_trim(env, "TEECHAT_SKILL_HUB_BINARY_SHA256")
        .unwrap_or(gateway_binary_sha256.as_str())
        .to_ascii_lowercase();
    let gateway_ed25519_public = env_trim(env, "TEECHAT_GATEWAY_ED25519_PUBLIC")
        .unwrap_or("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        .to_string();

    let allowed_gw = env_trim(env, "TEECHAT_ALLOWED_GATEWAY_BINARY_SHA256")
        .map(split_hashes)
        .unwrap_or_else(|| HashSet::from([gateway_binary_sha256.clone()]));
    let allowed_sh = env_trim(env, "TEECHAT_ALLOWED_SKILL_HUB_BINARY_SHA256")
        .map(split_hashes)
        .unwrap_or_else(|| HashSet::from([skill_hub_binary_sha256.clone()]));

    let platform_policy = PlatformAttestationPolicy {
        policy_id: engine_policy.policy_id.clone(),
        allowed_gateway_binary_sha256: allowed_gw,
        allowed_skill_hub_binary_sha256: allowed_sh,
        max_quote_age_ms: engine_policy.max_quote_age_ms,
    };

    PlatformPolicyGatewayAttestationVerifier {
        engine_policy,
        platform_policy,
        bind: PlatformAttestationBind {
            gateway_binary_sha256,
            skill_hub_binary_sha256,
            ed25519_public: gateway_ed25519_public,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_verifier_with_defaults() {
        let env = HashMap::new();
        let v = platform_policy_verifier_from_env(&env);
        assert!(!v.bind.gateway_binary_sha256.is_empty());
        assert!(v
            .platform_policy
            .allowed_gateway_binary_sha256
            .contains(&v.bind.gateway_binary_sha256));
    }
}
