//! Engine instance id normalization (port of `engine/instance-id.ts`).

use std::collections::HashMap;

pub const DEFAULT_ENGINE_INSTANCE_ID: &str = "default";

pub fn normalize_engine_instance_id(raw: Option<&str>) -> Result<String, String> {
    let v = raw.unwrap_or("").trim();
    if v.is_empty() {
        return Ok(DEFAULT_ENGINE_INSTANCE_ID.into());
    }
    let valid = v.len() <= 64
        && v
            .chars()
            .next()
            .map(|c| c.is_ascii_alphanumeric())
            .unwrap_or(false)
        && v.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c));
    if !valid {
        return Err(format!("invalid_instance_id:{v}"));
    }
    Ok(v.to_string())
}

pub fn engine_instance_id_from_env(env: &HashMap<String, String>) -> Result<String, String> {
    if let Some(explicit) = env.get("TEECHAT_ENGINE_INSTANCE_ID") {
        if !explicit.trim().is_empty() {
            return normalize_engine_instance_id(Some(explicit));
        }
    }
    if let Some(slot) = env.get("TEECHAT_ENGINE_SLOT").map(|s| s.trim()) {
        if slot == "blue" || slot == "green" {
            return Ok(slot.to_string());
        }
    }
    Ok(DEFAULT_ENGINE_INSTANCE_ID.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_instance_id_from_env_slot() {
        let mut env = HashMap::new();
        env.insert("TEECHAT_ENGINE_SLOT".into(), "green".into());
        assert_eq!(engine_instance_id_from_env(&env).unwrap(), "green");
    }

    #[test]
    fn normalize_rejects_invalid() {
        assert!(normalize_engine_instance_id(Some("bad id")).is_err());
    }
}
