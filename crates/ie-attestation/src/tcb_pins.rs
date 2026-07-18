use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::AttestationError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcbOpePin {
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(rename = "gitSha", default, skip_serializing_if = "Option::is_none")]
    pub git_sha: Option<String>,
    #[serde(rename = "libopeFfiSha256")]
    pub libope_ffi_sha256: String,
    #[serde(rename = "assetUrl", default, skip_serializing_if = "Option::is_none")]
    pub asset_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcbAttestedMtlsPin {
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(rename = "gitSha", default, skip_serializing_if = "Option::is_none")]
    pub git_sha: Option<String>,
    #[serde(rename = "libAttestedMtlsSha256")]
    pub lib_attested_mtls_sha256: String,
    #[serde(rename = "assetUrl", default, skip_serializing_if = "Option::is_none")]
    pub asset_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcbPins {
    pub schema: String,
    pub ope: TcbOpePin,
    #[serde(rename = "attestedMtls")]
    pub attested_mtls: TcbAttestedMtlsPin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcbPinsValidation {
    pub schema: String,
    pub ope_version: String,
    pub ope_ffi_sha256: String,
    pub attested_mtls_version: String,
    pub attested_mtls_sha256: String,
}

pub fn load_tcb_pins(path: impl AsRef<Path>) -> Result<TcbPins, AttestationError> {
    let path = path.as_ref();
    let text = fs::read_to_string(path).map_err(|source| AttestationError::Io {
        path: path.display().to_string(),
        source,
    })?;
    serde_json::from_str(&text).map_err(|source| AttestationError::Json {
        path: path.display().to_string(),
        source,
    })
}

fn is_lower_hex_sha256(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) && s == s.to_ascii_lowercase()
}

pub fn validate_tcb_pins(pins: &TcbPins) -> Result<TcbPinsValidation, AttestationError> {
    if !pins.schema.starts_with("teechat-inference-engine-tcb-pins/") {
        return Err(AttestationError::InvalidTcbPins {
            reason: format!("unexpected schema {}", pins.schema),
        });
    }
    if pins.ope.version.is_empty() {
        return Err(AttestationError::InvalidTcbPins {
            reason: "ope.version is required".into(),
        });
    }
    if !is_lower_hex_sha256(&pins.ope.libope_ffi_sha256) {
        return Err(AttestationError::InvalidTcbPins {
            reason: "ope.libopeFfiSha256 must be 64-char lowercase hex".into(),
        });
    }
    if pins.attested_mtls.version.is_empty() {
        return Err(AttestationError::InvalidTcbPins {
            reason: "attestedMtls.version is required".into(),
        });
    }
    if !is_lower_hex_sha256(&pins.attested_mtls.lib_attested_mtls_sha256) {
        return Err(AttestationError::InvalidTcbPins {
            reason: "attestedMtls.libAttestedMtlsSha256 must be 64-char lowercase hex".into(),
        });
    }
    Ok(TcbPinsValidation {
        schema: pins.schema.clone(),
        ope_version: pins.ope.version.clone(),
        ope_ffi_sha256: pins.ope.libope_ffi_sha256.clone(),
        attested_mtls_version: pins.attested_mtls.version.clone(),
        attested_mtls_sha256: pins.attested_mtls.lib_attested_mtls_sha256.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn repo_pins_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../config/tcb-pins.json")
    }

    #[test]
    fn validates_repo_pins() {
        let pins = load_tcb_pins(repo_pins_path()).unwrap();
        let v = validate_tcb_pins(&pins).unwrap();
        assert_eq!(v.ope_version, "0.1.0");
    }
}
