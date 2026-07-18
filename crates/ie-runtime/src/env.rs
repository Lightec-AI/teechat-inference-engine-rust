use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub type EnvMap = HashMap<String, String>;

fn load_env_file(path: &Path, env: &mut EnvMap) {
    let Ok(text) = fs::read_to_string(path) else {
        return;
    };
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let Some((key, value)) = t.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() || env.contains_key(key) {
            continue;
        }
        let mut value = value.trim().to_string();
        if (value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\''))
        {
            value = value[1..value.len() - 1].to_string();
        }
        env.insert(key.to_string(), value);
    }
}

/// Load `.env`, optional `.env.staging`, then `.env.local` into a map.
///
/// Does not override keys already present in `seed` (mirrors TS `loadEngineEnvFiles`).
pub fn load_engine_env_files(cwd: impl AsRef<Path>, seed: &mut EnvMap) {
    let cwd = cwd.as_ref();
    let staging = seed
        .get("TEECHAT_ENV")
        .map(|v| v.trim().eq_ignore_ascii_case("staging"))
        .unwrap_or(false)
        || cwd.join(".env.staging").exists();

    let files: &[&str] = if staging {
        &[".env", ".env.staging", ".env.local"]
    } else {
        &[".env", ".env.local"]
    };

    for name in files {
        load_env_file(&cwd.join(name), seed);
    }
}

pub fn env_map_from_process() -> EnvMap {
    std::env::vars().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn does_not_override_existing_keys() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".env"), "FOO=from_file\nBAR=baz\n").unwrap();
        let mut env = HashMap::from([("FOO".into(), "existing".into())]);
        load_engine_env_files(dir.path(), &mut env);
        assert_eq!(env.get("FOO").map(String::as_str), Some("existing"));
        assert_eq!(env.get("BAR").map(String::as_str), Some("baz"));
    }
}
