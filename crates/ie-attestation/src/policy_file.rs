//! On-disk attestation policy (ops `attestation-policy.prod.json`).
//! Fail-closed: missing file, invalid JSON, or empty required allowlists.

use std::collections::HashSet;
use std::path::Path;

use serde::Deserialize;
use thiserror::Error;

use crate::nv_cc::GpuAttestationPolicy;
use crate::policy::AttestationPolicy;

#[derive(Debug, Error)]
pub enum PolicyFileError {
    #[error("attestation policy file missing: {path}")]
    Missing { path: String },
    #[error("attestation policy invalid {field}: {path}")]
    Invalid { path: String, field: String },
    #[error("failed to read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse JSON at {path}: {source}")]
    Json {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("attestation policy empty allowlist {field}: {path}")]
    EmptyAllowlist { path: String, field: String },
}

/// Parsed ops policy file: engine quote allowlists plus gateway platform hashes.
#[derive(Debug, Clone)]
pub struct LoadedAttestationPolicyFile {
    pub engine_policy: AttestationPolicy,
    pub allowed_gateway_binary_sha256: HashSet<String>,
    pub allowed_skill_hub_binary_sha256: HashSet<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AttestationPolicyFileJson {
    policy_id: String,
    allowed_engine_binary_sha256: Vec<String>,
    allowed_vllm_binary_sha256: Vec<String>,
    #[serde(default)]
    allowed_gateway_binary_sha256: Vec<String>,
    #[serde(default)]
    allowed_skill_hub_binary_sha256: Vec<String>,
    max_quote_age_ms: u64,
    #[serde(default)]
    require_gpu_attestation: Option<bool>,
    #[serde(default)]
    allowed_gpu_driver_versions: Vec<String>,
    #[serde(default)]
    allowed_gpu_vbios_versions: Vec<String>,
    #[serde(default)]
    allowed_gpu_architectures: Vec<String>,
    #[serde(default)]
    max_gpu_evidence_age_ms: Option<u64>,
}

fn normalize_hashes(raw: &[String]) -> HashSet<String> {
    raw.iter()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

fn require_nonempty(
    hashes: HashSet<String>,
    field: &str,
    path: &str,
) -> Result<HashSet<String>, PolicyFileError> {
    if hashes.is_empty() {
        return Err(PolicyFileError::EmptyAllowlist {
            path: path.to_string(),
            field: field.to_string(),
        });
    }
    Ok(hashes)
}

/// Parse policy JSON bytes (same camelCase shape as TeeChat `attestation-policy-file.ts`).
pub fn parse_attestation_policy_json(
    bytes: &[u8],
    path: &str,
) -> Result<LoadedAttestationPolicyFile, PolicyFileError> {
    let rec: AttestationPolicyFileJson =
        serde_json::from_slice(bytes).map_err(|source| PolicyFileError::Json {
            path: path.to_string(),
            source,
        })?;
    let policy_id = rec.policy_id.trim();
    if policy_id.is_empty() {
        return Err(PolicyFileError::Invalid {
            path: path.to_string(),
            field: "policyId".into(),
        });
    }
    if rec.max_quote_age_ms == 0 {
        return Err(PolicyFileError::Invalid {
            path: path.to_string(),
            field: "maxQuoteAgeMs".into(),
        });
    }
    let engine = require_nonempty(
        normalize_hashes(&rec.allowed_engine_binary_sha256),
        "allowedEngineBinarySha256",
        path,
    )?;
    let vllm = require_nonempty(
        normalize_hashes(&rec.allowed_vllm_binary_sha256),
        "allowedVllmBinarySha256",
        path,
    )?;
    let gateway = require_nonempty(
        normalize_hashes(&rec.allowed_gateway_binary_sha256),
        "allowedGatewayBinarySha256",
        path,
    )?;
    let skill_hub = {
        let sh = normalize_hashes(&rec.allowed_skill_hub_binary_sha256);
        if sh.is_empty() {
            gateway.clone()
        } else {
            sh
        }
    };
    let max_gpu = rec.max_gpu_evidence_age_ms.unwrap_or(24 * 60 * 60 * 1000);
    if max_gpu == 0 {
        return Err(PolicyFileError::Invalid {
            path: path.to_string(),
            field: "maxGpuEvidenceAgeMs".into(),
        });
    }
    Ok(LoadedAttestationPolicyFile {
        engine_policy: AttestationPolicy {
            policy_id: policy_id.to_string(),
            allowed_engine_binary_sha256: engine,
            allowed_vllm_binary_sha256: vllm,
            max_quote_age_ms: rec.max_quote_age_ms,
            gpu: GpuAttestationPolicy {
                require_gpu_attestation: rec.require_gpu_attestation.unwrap_or(true),
                allowed_gpu_driver_versions: normalize_hashes(&rec.allowed_gpu_driver_versions),
                allowed_gpu_vbios_versions: normalize_hashes(&rec.allowed_gpu_vbios_versions),
                allowed_gpu_architectures: normalize_hashes(&rec.allowed_gpu_architectures),
                max_gpu_evidence_age_ms: max_gpu,
            },
        },
        allowed_gateway_binary_sha256: gateway,
        allowed_skill_hub_binary_sha256: skill_hub,
    })
}

pub fn load_attestation_policy_from_file(
    path: impl AsRef<Path>,
) -> Result<LoadedAttestationPolicyFile, PolicyFileError> {
    let path_ref = path.as_ref();
    let path_str = path_ref.display().to_string();
    if !path_ref.is_file() {
        return Err(PolicyFileError::Missing { path: path_str });
    }
    let bytes = std::fs::read(path_ref).map_err(|source| PolicyFileError::Io {
        path: path_str.clone(),
        source,
    })?;
    parse_attestation_policy_json(&bytes, &path_str)
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
    fn parses_camel_case_allowlists() {
        let loaded = parse_attestation_policy_json(MIN_JSON.as_bytes(), "mem").unwrap();
        assert_eq!(loaded.engine_policy.policy_id, "teechat-cpu-tee-prod-v1");
        assert!(loaded
            .engine_policy
            .allowed_engine_binary_sha256
            .contains("aa11111111111111111111111111111111111111111111111111111111111111"));
        assert!(loaded
            .allowed_gateway_binary_sha256
            .contains("cc33333333333333333333333333333333333333333333333333333333333333"));
        assert_eq!(
            loaded.allowed_skill_hub_binary_sha256,
            loaded.allowed_gateway_binary_sha256
        );
    }

    #[test]
    fn empty_engine_allowlist_fails_closed() {
        let json = MIN_JSON.replace(
            r#""allowedEngineBinarySha256": ["aa11111111111111111111111111111111111111111111111111111111111111"]"#,
            r#""allowedEngineBinarySha256": []"#,
        );
        let err = parse_attestation_policy_json(json.as_bytes(), "mem").unwrap_err();
        assert!(matches!(
            err,
            PolicyFileError::EmptyAllowlist { field, .. } if field == "allowedEngineBinarySha256"
        ));
    }

    #[test]
    fn empty_gateway_allowlist_fails_closed() {
        let json = MIN_JSON.replace(
            r#""allowedGatewayBinarySha256": ["cc33333333333333333333333333333333333333333333333333333333333333"]"#,
            r#""allowedGatewayBinarySha256": []"#,
        );
        let err = parse_attestation_policy_json(json.as_bytes(), "mem").unwrap_err();
        assert!(matches!(
            err,
            PolicyFileError::EmptyAllowlist { field, .. } if field == "allowedGatewayBinarySha256"
        ));
    }

    #[test]
    fn missing_file_fails_closed() {
        let err =
            load_attestation_policy_from_file("/no/such/attestation-policy.json").unwrap_err();
        assert!(matches!(err, PolicyFileError::Missing { .. }));
    }

    #[test]
    fn loads_from_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.json");
        std::fs::write(&path, MIN_JSON).unwrap();
        let loaded = load_attestation_policy_from_file(&path).unwrap();
        assert_eq!(loaded.engine_policy.policy_id, "teechat-cpu-tee-prod-v1");
    }

    #[test]
    fn parses_teechat_prod_policy_if_present() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../TeaChat/config/attestation-policy.prod.json");
        if !path.is_file() {
            return;
        }
        let loaded = load_attestation_policy_from_file(&path).expect("prod policy");
        assert_eq!(loaded.engine_policy.policy_id, "teechat-cpu-tee-prod-v1");
        assert!(!loaded.engine_policy.allowed_engine_binary_sha256.is_empty());
        assert!(!loaded.allowed_gateway_binary_sha256.is_empty());
    }
}
