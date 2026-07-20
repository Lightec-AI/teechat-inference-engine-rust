//! Verify AMD SNP report signatures via snpguest (port of `sev-snp/verify-report.ts`).

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::guest_report::sev_snp_guest_bin_from_env;

const REPORT_DATA_OFFSET: usize = 0x50;
const REPORT_DATA_LEN: usize = 64;

pub fn extract_report_data_from_report(report: &[u8]) -> Option<[u8; 64]> {
    if report.len() < REPORT_DATA_OFFSET + REPORT_DATA_LEN {
        return None;
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&report[REPORT_DATA_OFFSET..REPORT_DATA_OFFSET + REPORT_DATA_LEN]);
    Some(out)
}

fn snp_cert_cache_dir(env: &HashMap<String, String>) -> PathBuf {
    env.get("TEECHAT_SNP_CERT_CACHE_DIR")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/cache/teechat/snp-certs"))
}

fn snp_cpu_family(env: &HashMap<String, String>) -> String {
    env.get("TEECHAT_SNP_CPU_FAMILY")
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "milan".into())
}

fn ensure_snp_certificates(report_path: &Path, env: &HashMap<String, String>) -> Result<PathBuf, ()> {
    let cache = snp_cert_cache_dir(env);
    fs::create_dir_all(&cache).map_err(|_| ())?;
    let bin = match sev_snp_guest_bin_from_env(env) {
        Ok(b) => b,
        Err(_) => return Err(()),
    };
    let vcek = cache.join("vcek.pem");
    if !vcek.exists() {
        let status = Command::new(&bin)
            .args(["fetch", "vcek", "pem", cache.to_str().unwrap(), report_path.to_str().unwrap()])
            .status()
            .map_err(|_| ())?;
        if !status.success() {
            return Err(());
        }
    }
    let ark = cache.join("ark.pem");
    if !ark.exists() {
        let family = snp_cpu_family(env);
        let status = Command::new(&bin)
            .args(["fetch", "ca", "pem", cache.to_str().unwrap(), &family])
            .status()
            .map_err(|_| ())?;
        if !status.success() {
            return Err(());
        }
    }
    Ok(cache)
}

pub fn verify_sev_snp_attestation_report(
    report: &[u8],
    expected_report_data: &[u8; 64],
    env: &HashMap<String, String>,
) -> bool {
    let embedded = extract_report_data_from_report(report);
    let Some(embedded) = embedded else {
        return false;
    };
    if embedded != *expected_report_data {
        return false;
    }
    let bin = match sev_snp_guest_bin_from_env(env) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(_) => return false,
    };
    let report_path = dir.path().join("report.bin");
    if fs::write(&report_path, report).is_err() {
        return false;
    }
    let certs = match ensure_snp_certificates(&report_path, env) {
        Ok(c) => c,
        Err(_) => return false,
    };
    if Command::new(&bin)
        .args(["verify", "certs", certs.to_str().unwrap()])
        .status()
        .map(|s| !s.success())
        .unwrap_or(true)
    {
        return false;
    }
    let out = Command::new(&bin)
        .args([
            "verify",
            "attestation",
            certs.to_str().unwrap(),
            report_path.to_str().unwrap(),
        ])
        .output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .contains("VEK signed the Attestation Report"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_report_data_requires_minimum_length() {
        assert!(extract_report_data_from_report(&[0u8; 10]).is_none());
    }
}
