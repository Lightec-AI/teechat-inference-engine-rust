//! SEV-SNP guest report I/O (port of `sev-snp/guest-report.ts`).

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::error::AttestationError;

pub fn sev_snp_guest_bin_from_env(env: &HashMap<String, String>) -> Result<String, AttestationError> {
    let raw = env
        .get("TEECHAT_SNP_GUEST_BIN")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("snpguest");
    resolve_snpguest_bin(raw)
}

/// Allowlist `snpguest` basename or absolute paths under `/usr/bin` / `/usr/local/bin`.
pub fn resolve_snpguest_bin(raw: &str) -> Result<String, AttestationError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.contains("..") {
        return Err(AttestationError::InvalidSnpGuestBin(trimmed.into()));
    }
    let path = Path::new(trimmed);
    if path.is_absolute() {
        let allowed_prefixes = ["/usr/bin/", "/usr/local/bin/"];
        let s = path.to_string_lossy();
        if allowed_prefixes.iter().any(|p| s.starts_with(p))
            && path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n == "snpguest")
        {
            return Ok(s.into_owned());
        }
        return Err(AttestationError::InvalidSnpGuestBin(trimmed.into()));
    }
    if trimmed == "snpguest" {
        return Ok("snpguest".into());
    }
    Err(AttestationError::InvalidSnpGuestBin(trimmed.into()))
}

pub fn is_sev_snp_guest_device_available() -> bool {
    Path::new("/dev/sev-guest").exists()
}

pub fn is_sev_snp_guest_tool_available(env: &HashMap<String, String>) -> bool {
    let Ok(bin) = sev_snp_guest_bin_from_env(env) else {
        return false;
    };
    Command::new(&bin)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn should_use_sev_snp_attestation(env: &HashMap<String, String>) -> bool {
    let kind = env
        .get("TEECHAT_CPU_TEE_KIND")
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();
    if matches!(kind.as_str(), "sev-snp" | "snp") {
        return true;
    }
    if matches!(kind.as_str(), "fixture" | "mock" | "tdx") {
        return false;
    }
    is_sev_snp_guest_device_available() && is_sev_snp_guest_tool_available(env)
}

/// Request an AMD SNP attestation report with 64-byte REPORT_DATA.
#[cfg(unix)]
pub fn request_sev_snp_attestation_report(
    report_data_64: &[u8; 64],
    env: &HashMap<String, String>,
) -> Result<Vec<u8>, AttestationError> {
    if !is_sev_snp_guest_device_available() {
        return Err(AttestationError::SevGuestUnavailable);
    }
    let bin = sev_snp_guest_bin_from_env(env)?;
    let dir = tempfile::tempdir().map_err(|source| AttestationError::Io {
        path: "tempdir".into(),
        source,
    })?;
    let req_path = dir.path().join("request.bin");
    let report_path = dir.path().join("report.bin");
    fs::write(&req_path, report_data_64).map_err(|source| AttestationError::Io {
        path: req_path.display().to_string(),
        source,
    })?;
    let status = Command::new(&bin)
        .args(["report", report_path.to_str().unwrap(), req_path.to_str().unwrap()])
        .status()
        .map_err(|source| AttestationError::ToolInvoke {
            bin: bin.clone(),
            source,
        })?;
    if !status.success() {
        return Err(AttestationError::ToolFailed { bin });
    }
    fs::read(&report_path).map_err(|source| AttestationError::Io {
        path: report_path.display().to_string(),
        source,
    })
}

#[cfg(not(unix))]
pub fn request_sev_snp_attestation_report(
    _report_data_64: &[u8; 64],
    _env: &HashMap<String, String>,
) -> Result<Vec<u8>, AttestationError> {
    Err(AttestationError::SevGuestUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_use_sev_snp_respects_env_kind() {
        let mut env = HashMap::new();
        env.insert("TEECHAT_CPU_TEE_KIND".into(), "mock".into());
        assert!(!should_use_sev_snp_attestation(&env));
        env.insert("TEECHAT_CPU_TEE_KIND".into(), "sev-snp".into());
        assert!(should_use_sev_snp_attestation(&env));
    }

    #[test]
    fn rejects_arbitrary_snpguest_path() {
        assert!(resolve_snpguest_bin("/tmp/evil").is_err());
        assert!(resolve_snpguest_bin("../snpguest").is_err());
        assert_eq!(resolve_snpguest_bin("snpguest").unwrap(), "snpguest");
        assert_eq!(
            resolve_snpguest_bin("/usr/bin/snpguest").unwrap(),
            "/usr/bin/snpguest"
        );
    }

    #[test]
    #[ignore = "requires /dev/sev-guest and snpguest"]
    fn request_sev_snp_attestation_report_hardware() {
        let env = HashMap::new();
        let data = [0u8; 64];
        let _ = request_sev_snp_attestation_report(&data, &env).expect("hardware");
    }
}
