//! Runtime pool / gateway control file paths (port of ops JSON control files).

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

/// Resolve and validate a control-file path.
///
/// Allowed:
/// - under `/etc/teechat/`
/// - under `TEECHAT_ENGINE_CONTROL_DIR` (tests / local stub smoke)
///
/// Rejects `..` components and empty overrides.
pub fn resolve_control_file_path(
    raw: &str,
    env: &HashMap<String, String>,
) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("empty control file path".into());
    }
    let path = PathBuf::from(trimmed);
    if path
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(format!("control path must not contain '..': {trimmed}"));
    }
    if !is_allowed_control_path(&path, env) {
        return Err(format!(
            "control path not allowed (must be under /etc/teechat/ or TEECHAT_ENGINE_CONTROL_DIR): {trimmed}"
        ));
    }
    Ok(trimmed.to_string())
}

fn is_allowed_control_path(path: &Path, env: &HashMap<String, String>) -> bool {
    let s = path.to_string_lossy();
    if s.starts_with("/etc/teechat/") {
        return true;
    }
    if let Some(root) = env
        .get("TEECHAT_ENGINE_CONTROL_DIR")
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
    {
        let root = root.trim_end_matches('/');
        if s == root || s.starts_with(&format!("{root}/")) {
            return true;
        }
    }
    false
}

fn resolve_or_default(
    env: &HashMap<String, String>,
    override_key: &str,
    default: String,
) -> String {
    if let Some(path) = env.get(override_key) {
        let t = path.trim();
        if !t.is_empty() {
            return resolve_control_file_path(t, env).unwrap_or_else(|err| {
                eprintln!("[engine-controls] {err}; falling back to default");
                default
            });
        }
    }
    // defaults under /etc/teechat are always allowed
    default
}

pub fn default_pool_drain_file(env: &HashMap<String, String>) -> String {
    resolve_or_default(
        env,
        "TEECHAT_ENGINE_POOL_DRAIN_FILE",
        slot_path(env, "engine-pool-drain", "/etc/teechat/engine-pool-drain.json"),
    )
}

pub fn default_pool_scale_file(env: &HashMap<String, String>) -> String {
    resolve_or_default(
        env,
        "TEECHAT_ENGINE_POOL_SCALE_FILE",
        slot_path(env, "engine-pool-scale", "/etc/teechat/engine-pool-scale.json"),
    )
}

pub fn default_pool_status_file(env: &HashMap<String, String>) -> String {
    resolve_or_default(
        env,
        "TEECHAT_ENGINE_POOL_STATUS_FILE",
        slot_path(env, "engine-pool-status", "/etc/teechat/engine-pool-status.json"),
    )
}

pub fn default_gateway_migration_file(env: &HashMap<String, String>) -> String {
    resolve_or_default(
        env,
        "TEECHAT_ENGINE_GATEWAY_MIGRATION_FILE",
        "/etc/teechat/engine-gateway-migration.json".into(),
    )
}

fn slot_path(env: &HashMap<String, String>, stem: &str, fallback: &str) -> String {
    match env
        .get("TEECHAT_ENGINE_SLOT")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        Some(slot) => format!("/etc/teechat/{stem}-{slot}.json"),
        None => fallback.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_pool_drain_file_uses_slot() {
        let mut env = HashMap::new();
        env.insert("TEECHAT_ENGINE_SLOT".into(), "green".into());
        assert_eq!(
            default_pool_drain_file(&env),
            "/etc/teechat/engine-pool-drain-green.json"
        );
    }

    #[test]
    fn rejects_parent_dir_escape() {
        let env = HashMap::new();
        assert!(resolve_control_file_path("/etc/teechat/../passwd", &env).is_err());
    }

    #[test]
    fn allows_control_dir_override() {
        let mut env = HashMap::new();
        env.insert("TEECHAT_ENGINE_CONTROL_DIR".into(), "/tmp/ie-controls".into());
        assert_eq!(
            resolve_control_file_path("/tmp/ie-controls/drain.json", &env).unwrap(),
            "/tmp/ie-controls/drain.json"
        );
    }
}
