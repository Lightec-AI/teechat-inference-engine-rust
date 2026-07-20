use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::error::AttestationError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpeIdentityMeasurements {
    pub version: String,
    pub git_sha: String,
    pub libope_ffi_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedMtlsIdentityMeasurements {
    pub version: String,
    pub git_sha: String,
    pub lib_attested_mtls_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryMeasurements {
    pub engine_version: String,
    pub engine_binary_sha256: String,
    pub vllm_version: String,
    pub vllm_binary_sha256: String,
    pub ope: Option<OpeIdentityMeasurements>,
    pub attested_mtls: Option<AttestedMtlsIdentityMeasurements>,
}

fn sha256_file(path: &Path) -> Result<String, AttestationError> {
    let data = fs::read(path).map_err(|source| AttestationError::Io {
        path: path.display().to_string(),
        source,
    })?;
    Ok(format!("{:x}", Sha256::digest(data)))
}

fn read_json_file<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, AttestationError> {
    let text = fs::read_to_string(path).map_err(|source| AttestationError::Io {
        path: path.display().to_string(),
        source,
    })?;
    serde_json::from_str(&text).map_err(|source| AttestationError::Json {
        path: path.display().to_string(),
        source,
    })
}

#[derive(Debug, Default, Deserialize)]
struct ReleaseManifest {
    #[serde(rename = "ieRuntimeSha256")]
    ie_runtime_sha256: Option<String>,
    #[serde(rename = "opeFfiSha256")]
    ope_ffi_sha256: Option<String>,
    #[serde(rename = "attestedMtlsSha256")]
    attested_mtls_sha256: Option<String>,
    version: Option<String>,
    #[serde(rename = "opeGitSha")]
    ope_git_sha: Option<String>,
    #[serde(rename = "opeVersion")]
    ope_version: Option<String>,
    #[serde(rename = "attestedMtlsVersion")]
    attested_mtls_version: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct OpeVersionPin {
    version: Option<String>,
    #[serde(rename = "gitSha")]
    git_sha: Option<String>,
    #[serde(rename = "libopeFfiSha256")]
    libope_ffi_sha256: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct AttestedMtlsPin {
    version: Option<String>,
    #[serde(rename = "gitSha")]
    git_sha: Option<String>,
    #[serde(rename = "libAttestedMtlsSha256")]
    lib_attested_mtls_sha256: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct TcbPinsPartial {
    ope: Option<OpeVersionPin>,
    #[serde(rename = "attestedMtls")]
    attested_mtls: Option<AttestedMtlsPin>,
}

fn read_release_manifest(root: &Path) -> Option<ReleaseManifest> {
    let path = root.join("RELEASE_MANIFEST.json");
    read_json_file(&path).ok()
}

fn read_ope_version_pin(root: &Path) -> Option<OpeVersionPin> {
    for rel in ["config/ope-version.json", "ope-version.json"] {
        let path = root.join(rel);
        if path.exists() {
            if let Ok(pin) = read_json_file::<OpeVersionPin>(&path) {
                return Some(pin);
            }
        }
    }
    None
}

fn read_attested_mtls_pin(root: &Path) -> Option<AttestedMtlsPin> {
    for rel in [
        "config/attested-mtls-version.json",
        "attested-mtls-version.json",
        "tcb-pins.json",
    ] {
        let path = root.join(rel);
        if !path.exists() {
            continue;
        }
        if let Ok(raw) = read_json_file::<serde_json::Value>(&path) {
            if let Some(obj) = raw.get("attestedMtls").and_then(|v| v.as_object()) {
                return Some(AttestedMtlsPin {
                    version: obj
                        .get("version")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                    git_sha: obj
                        .get("gitSha")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                    lib_attested_mtls_sha256: obj
                        .get("libAttestedMtlsSha256")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                });
            }
            if let Ok(pin) = serde_json::from_value::<AttestedMtlsPin>(raw) {
                return Some(pin);
            }
        }
    }
    None
}

fn read_tcb_pins_partial(root: &Path) -> Option<TcbPinsPartial> {
    let path = root.join("config/tcb-pins.json");
    if !path.exists() {
        return None;
    }
    read_json_file(&path).ok()
}

fn env_trim(env: &HashMap<String, String>, key: &str) -> Option<String> {
    env.get(key)
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

/// Resolve engine runtime + vLLM + independent OPE / attested-mtls measurement hashes.
///
/// `engine_binary_sha256` is the IE runtime tarball/bundle — **not** `libope_ffi.so`.
pub fn resolve_binary_measurements_from_env(
    env: &HashMap<String, String>,
    root: impl AsRef<Path>,
) -> Result<BinaryMeasurements, AttestationError> {
    let root = root.as_ref();
    let manifest = read_release_manifest(root);
    let ope_pin = read_ope_version_pin(root);
    let amt_pin = read_attested_mtls_pin(root);
    let tcb = read_tcb_pins_partial(root);

    let engine_sha = env_trim(env, "TEECHAT_ENGINE_BINARY_SHA256")
        .or_else(|| env_trim(env, "TEECHAT_IE_RUNTIME_SHA256"))
        .or_else(|| manifest.as_ref()?.ie_runtime_sha256.clone())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    let engine_version = env_trim(env, "TEECHAT_ENGINE_BUILD_VERSION")
        .or_else(|| manifest.as_ref()?.version.clone())
        .unwrap_or_else(|| "prod".to_string());

    let mut vllm_sha = env_trim(env, "TEECHAT_VLLM_BINARY_SHA256")
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    if vllm_sha.is_empty() {
        if let Some(path) = env_trim(env, "TEECHAT_VLLM_BINARY_PATH") {
            vllm_sha = sha256_file(Path::new(&path))?;
        }
    }

    let vllm_version = env_trim(env, "TEECHAT_VLLM_BUILD_VERSION")
        .unwrap_or_else(|| "upstream".to_string());

    if engine_sha.is_empty() {
        return Err(AttestationError::MissingEngineSha);
    }
    if vllm_sha.is_empty() {
        return Err(AttestationError::MissingVllmSha);
    }

    let ope_version = env_trim(env, "TEECHAT_OPE_VERSION")
        .or_else(|| manifest.as_ref()?.ope_version.clone())
        .or_else(|| ope_pin.as_ref()?.version.clone())
        .or_else(|| tcb.as_ref()?.ope.as_ref()?.version.clone())
        .unwrap_or_default();

    let ope_git_sha = env_trim(env, "TEECHAT_OPE_GIT_SHA")
        .or_else(|| manifest.as_ref()?.ope_git_sha.clone())
        .or_else(|| ope_pin.as_ref()?.git_sha.clone())
        .or_else(|| tcb.as_ref()?.ope.as_ref()?.git_sha.clone())
        .unwrap_or_default();

    let ope_ffi_sha = env_trim(env, "TEECHAT_OPE_FFI_SHA256")
        .or_else(|| manifest.as_ref()?.ope_ffi_sha256.clone())
        .or_else(|| ope_pin.as_ref()?.libope_ffi_sha256.clone())
        .or_else(|| tcb.as_ref()?.ope.as_ref()?.libope_ffi_sha256.clone())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    let ope = if !ope_version.is_empty() && !ope_ffi_sha.is_empty() {
        Some(OpeIdentityMeasurements {
            version: ope_version,
            git_sha: if ope_git_sha.is_empty() {
                "unknown".into()
            } else {
                ope_git_sha
            },
            libope_ffi_sha256: ope_ffi_sha,
        })
    } else {
        None
    };

    let amt_version = env_trim(env, "TEECHAT_ATTESTED_MTLS_VERSION")
        .or_else(|| manifest.as_ref()?.attested_mtls_version.clone())
        .or_else(|| amt_pin.as_ref()?.version.clone())
        .or_else(|| tcb.as_ref()?.attested_mtls.as_ref()?.version.clone())
        .unwrap_or_default();

    let amt_git_sha = env_trim(env, "TEECHAT_ATTESTED_MTLS_GIT_SHA")
        .or_else(|| amt_pin.as_ref()?.git_sha.clone())
        .or_else(|| tcb.as_ref()?.attested_mtls.as_ref()?.git_sha.clone())
        .unwrap_or_default();

    let amt_sha = env_trim(env, "TEECHAT_ATTESTED_MTLS_SHA256")
        .or_else(|| manifest.as_ref()?.attested_mtls_sha256.clone())
        .or_else(|| amt_pin.as_ref()?.lib_attested_mtls_sha256.clone())
        .or_else(|| {
            tcb.as_ref()?
                .attested_mtls
                .as_ref()?
                .lib_attested_mtls_sha256
                .clone()
        })
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    let attested_mtls = if !amt_version.is_empty() && !amt_sha.is_empty() {
        Some(AttestedMtlsIdentityMeasurements {
            version: amt_version,
            git_sha: if amt_git_sha.is_empty() {
                "unknown".into()
            } else {
                amt_git_sha
            },
            lib_attested_mtls_sha256: amt_sha,
        })
    } else {
        None
    };

    Ok(BinaryMeasurements {
        engine_version,
        engine_binary_sha256: engine_sha,
        vllm_version,
        vllm_binary_sha256: vllm_sha,
        ope,
        attested_mtls,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn engine_sha_distinct_from_ope_ffi_and_attested_mtls() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("config")).unwrap();
        fs::write(
            dir.path().join("config/tcb-pins.json"),
            include_str!("../../../config/tcb-pins.json"),
        )
        .unwrap();

        let mut env = HashMap::new();
        env.insert(
            "TEECHAT_ENGINE_BINARY_SHA256".into(),
            "aa".repeat(32),
        );
        env.insert(
            "TEECHAT_VLLM_BINARY_SHA256".into(),
            "bb".repeat(32),
        );

        let m = resolve_binary_measurements_from_env(&env, dir.path()).unwrap();
        assert_eq!(m.engine_binary_sha256, "aa".repeat(32));
        let ope = m.ope.as_ref().unwrap();
        let amt = m.attested_mtls.as_ref().unwrap();
        assert_ne!(m.engine_binary_sha256, ope.libope_ffi_sha256);
        assert_ne!(m.engine_binary_sha256, amt.lib_attested_mtls_sha256);
        assert_ne!(ope.libope_ffi_sha256, amt.lib_attested_mtls_sha256);
    }
}
