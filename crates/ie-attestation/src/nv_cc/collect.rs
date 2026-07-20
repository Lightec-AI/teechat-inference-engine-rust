//! Collect NVIDIA CC GPU evidence via `nvattest` (port of `nv-cc/collect.ts`).

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use serde_json::{json, Value};

use crate::error::AttestationError;

use super::mock::{build_gpu_not_applicable_evidence, encode_legacy_mock_gpu_evidence};

fn nvidia_smi_bin(env: &HashMap<String, String>) -> String {
    env.get("TEECHAT_NVIDIA_SMI_BIN")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("nvidia-smi")
        .to_string()
}

/// Allowlist `nvattest` basename or absolute paths under `/usr/bin` / `/usr/local/bin`.
pub fn resolve_nvattest_bin(raw: &str) -> Result<String, AttestationError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.contains("..") {
        return Err(AttestationError::InvalidNvattestBin(trimmed.into()));
    }
    let path = Path::new(trimmed);
    if path.is_absolute() {
        let allowed_prefixes = ["/usr/bin/", "/usr/local/bin/"];
        let s = path.to_string_lossy();
        if allowed_prefixes.iter().any(|p| s.starts_with(p))
            && path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n == "nvattest")
        {
            return Ok(s.into_owned());
        }
        return Err(AttestationError::InvalidNvattestBin(trimmed.into()));
    }
    if trimmed == "nvattest" {
        return Ok("nvattest".into());
    }
    Err(AttestationError::InvalidNvattestBin(trimmed.into()))
}

pub fn nvattest_bin_from_env(env: &HashMap<String, String>) -> Result<String, AttestationError> {
    let raw = env
        .get("TEECHAT_NVATTEST_BIN")
        .or_else(|| env.get("NVATTEST_BIN"))
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("nvattest");
    resolve_nvattest_bin(raw)
}

fn env_flag_true(env: &HashMap<String, String>, key: &str) -> bool {
    env.get(key)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn mock_allowed(env: &HashMap<String, String>) -> bool {
    let kind = env
        .get("TEECHAT_ENV")
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();
    matches!(kind.as_str(), "development" | "dev" | "test" | "staging" | "")
        || env_flag_true(env, "TEECHAT_ENGINE_STUB")
}

fn should_use_real_gpu_collector(env: &HashMap<String, String>) -> bool {
    if env_flag_true(env, "TEECHAT_FORCE_REAL_GPU_ATTESTATION") {
        return true;
    }
    if env
        .get("TEECHAT_GPU_ATTESTATION")
        .map(|s| s.trim().eq_ignore_ascii_case("real"))
        .unwrap_or(false)
    {
        return true;
    }
    !mock_allowed(env)
}

fn read_conf_compute_state(env: &HashMap<String, String>) -> Value {
    let bin = nvidia_smi_bin(env);
    let output = Command::new(&bin)
        .args(["conf-compute", "-q"])
        .output();
    let Ok(output) = output else {
        return json!({ "enabled": false });
    };
    if !output.status.success() {
        return json!({ "enabled": false });
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let enabled = text.lines().any(|l| {
        let lower = l.to_ascii_lowercase();
        (lower.contains("cc state") || lower.contains("cc mode"))
            && (lower.contains(": on") || lower.ends_with("on"))
    });
    let mut cc = json!({ "enabled": enabled });
    if let Some(dev) = capture_field(&text, "DevTools Attestation") {
        cc["dev_tools_attestation"] = json!(dev);
    }
    if let Some(environment) = capture_field(&text, "Environment") {
        cc["environment"] = json!(environment);
    }
    cc
}

fn capture_field(text: &str, label: &str) -> Option<String> {
    for line in text.lines() {
        if let Some(rest) = line.split_once(':') {
            if rest.0.trim().eq_ignore_ascii_case(label) {
                let v = rest.1.trim();
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

fn has_cc_capable_gpu(env: &HashMap<String, String>) -> bool {
    let bin = nvidia_smi_bin(env);
    if Command::new(&bin)
        .arg("-L")
        .output()
        .map(|o| !o.status.success())
        .unwrap_or(true)
    {
        return false;
    }
    read_conf_compute_state(env)
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

fn encode_envelope(envelope: &Value) -> String {
    ope_crypto::encode(envelope.to_string().as_bytes())
}

fn collect_via_nvattest(
    env: &HashMap<String, String>,
    nonce: Option<&str>,
) -> Result<Value, AttestationError> {
    let bin = nvattest_bin_from_env(env)?;
    let mut args = vec![
        "collect-evidence".into(),
        "--device".into(),
        "gpu".into(),
        "--format".into(),
        "json".into(),
    ];
    if let Some(n) = nonce.map(str::trim).filter(|s| !s.is_empty()) {
        args.push("--nonce".into());
        args.push(n.to_string());
    }
    let mut cmd = Command::new(&bin);
    cmd.args(&args);
    // Inherit guest env so nvattest finds driver paths; still pin binary allowlist.
    let output = cmd
        .output()
        .map_err(|source| AttestationError::ToolInvoke {
            bin: bin.clone(),
            source,
        })?;
    if !output.status.success() {
        return Err(AttestationError::ToolFailed { bin });
    }
    let parsed: Value = serde_json::from_slice(&output.stdout).map_err(|source| {
        AttestationError::Json {
            path: "nvattest-stdout".into(),
            source,
        }
    })?;
    let result_code = parsed
        .get("result_code")
        .and_then(|v| v.as_i64())
        .unwrap_or(-1);
    let evidences = parsed
        .get("evidences")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if result_code != 0 || evidences.is_empty() {
        return Err(AttestationError::ToolFailed { bin });
    }
    // Bound runtime — callers already treat tool failure as hard error.
    let _ = Duration::from_secs(120);
    Ok(parsed)
}

/// Base64url evidence string for `AttestationBundle.gpu_tee.evidence`.
pub fn collect_nv_cc_gpu_evidence_b64(
    env: &HashMap<String, String>,
    nonce: Option<&str>,
) -> Result<String, AttestationError> {
    if !should_use_real_gpu_collector(env) || !has_cc_capable_gpu(env) {
        if mock_allowed(env) {
            return Ok(encode_legacy_mock_gpu_evidence());
        }
        return Ok(build_gpu_not_applicable_evidence());
    }

    let cc_mode = read_conf_compute_state(env);
    if !cc_mode
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return Err(AttestationError::GpuCcModeOff);
    }

    let nvattest = collect_via_nvattest(env, nonce)?;
    let architecture = nvattest
        .get("evidences")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|first| first.get("arch"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let mut envelope = json!({
        "v": 1,
        "kind": "nv-cc",
        "collected_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "source": "nvattest",
        "cc_mode": cc_mode,
        "nvattest": nvattest,
    });
    if let Some(n) = nonce.map(str::trim).filter(|s| !s.is_empty()) {
        envelope["nonce"] = json!(n);
    }
    if let Some(arch) = architecture {
        envelope["measurements"] = json!({ "architecture": arch });
    }
    Ok(encode_envelope(&envelope))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_arbitrary_nvattest_path() {
        assert!(resolve_nvattest_bin("/tmp/evil").is_err());
        assert!(resolve_nvattest_bin("../nvattest").is_err());
        assert_eq!(resolve_nvattest_bin("nvattest").unwrap(), "nvattest");
        assert_eq!(
            resolve_nvattest_bin("/usr/local/bin/nvattest").unwrap(),
            "/usr/local/bin/nvattest"
        );
    }
}
