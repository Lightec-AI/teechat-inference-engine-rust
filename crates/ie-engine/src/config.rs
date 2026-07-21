use std::collections::HashMap;

use crate::cutover::{boot_pool_session_count, pool_baseline_from_env};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolReconnectConfig {
    pub fail_threshold: u32,
    pub fail_window_ms: u64,
    pub circuit_ms: u64,
    pub reconnect_base_ms: u64,
    pub reconnect_max_ms: u64,
}

impl Default for PoolReconnectConfig {
    fn default() -> Self {
        Self {
            fail_threshold: 8,
            fail_window_ms: 10_000,
            circuit_ms: 30_000,
            reconnect_base_ms: 1_000,
            reconnect_max_ms: 30_000,
        }
    }
}

impl PoolReconnectConfig {
    pub fn from_env(env: &HashMap<String, String>) -> Self {
        let mut cfg = Self::default();
        if let Some(v) = env.get("TEECHAT_ENGINE_POOL_RECONNECT_FAIL_THRESHOLD") {
            if let Ok(n) = v.parse::<u32>() {
                cfg.fail_threshold = n.max(1);
            }
        }
        if let Some(v) = env.get("TEECHAT_ENGINE_POOL_RECONNECT_FAIL_WINDOW_MS") {
            if let Ok(n) = v.parse::<u64>() {
                cfg.fail_window_ms = n.max(1_000);
            }
        }
        if let Some(v) = env.get("TEECHAT_ENGINE_POOL_RECONNECT_CIRCUIT_MS") {
            if let Ok(n) = v.parse::<u64>() {
                cfg.circuit_ms = n.max(1_000);
            }
        }
        cfg
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SupervisedPoolConfig {
    pub pool_target_size: u32,
    /// Used only when `pool_initial_fraction_explicit` is true.
    pub pool_initial_fraction: f64,
    pub pool_initial_fraction_explicit: bool,
    /// Floor when applying gateway desired-pool hints (default 4).
    pub pool_baseline: u32,
    pub supervised: bool,
    pub reconnect: PoolReconnectConfig,
}

impl SupervisedPoolConfig {
    pub fn from_env(env: &HashMap<String, String>) -> Self {
        let pool_target_size = env
            .get("TEECHAT_ENGINE_POOL_TARGET_SIZE")
            .or_else(|| env.get("TEECHAT_OPE_ENGINE_POOL_TARGET_SIZE"))
            .and_then(|v| v.parse().ok())
            .unwrap_or(1)
            .max(1);
        let fraction_raw = env
            .get("TEECHAT_ENGINE_POOL_INITIAL_FRACTION")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let pool_initial_fraction_explicit = fraction_raw.is_some();
        let pool_initial_fraction: f64 = fraction_raw
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(1.0_f64)
            .clamp(0.0_f64, 1.0_f64);
        let pool_baseline = pool_baseline_from_env(env);
        let supervised = !env
            .get("TEECHAT_ENGINE_SUPERVISED")
            .map(|v| v.eq_ignore_ascii_case("false") || v == "0")
            .unwrap_or(false);
        Self {
            pool_target_size,
            pool_initial_fraction,
            pool_initial_fraction_explicit,
            pool_baseline,
            supervised,
            reconnect: PoolReconnectConfig::from_env(env),
        }
    }

    pub fn initial_session_count(&self) -> u32 {
        // Mirror `boot_pool_session_count` without re-reading env: explicit fraction
        // uses cutover math; otherwise min(baseline, target).
        if self.pool_initial_fraction_explicit {
            crate::cutover::initial_pool_session_count(
                self.pool_target_size,
                self.pool_initial_fraction,
            )
        } else {
            self.pool_baseline.min(self.pool_target_size)
        }
    }

    /// Same as [`Self::initial_session_count`] but honors a full env map (tests / overrides).
    pub fn boot_session_count_from_env(&self, env: &HashMap<String, String>) -> u32 {
        let fraction = if self.pool_initial_fraction_explicit {
            Some(self.pool_initial_fraction)
        } else {
            None
        };
        boot_pool_session_count(self.pool_target_size, env, fraction)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_fraction_halves_boot_connects() {
        let cfg = SupervisedPoolConfig {
            pool_target_size: 4,
            pool_initial_fraction: 0.5,
            pool_initial_fraction_explicit: true,
            pool_baseline: 4,
            supervised: true,
            reconnect: PoolReconnectConfig::default(),
        };
        assert_eq!(cfg.initial_session_count(), 2);
    }

    #[test]
    fn default_boot_uses_baseline() {
        let cfg = SupervisedPoolConfig {
            pool_target_size: 32,
            pool_initial_fraction: 1.0,
            pool_initial_fraction_explicit: false,
            pool_baseline: 4,
            supervised: true,
            reconnect: PoolReconnectConfig::default(),
        };
        assert_eq!(cfg.initial_session_count(), 4);
    }

    #[test]
    fn from_env_baseline_when_fraction_unset() {
        let mut env = HashMap::new();
        env.insert("TEECHAT_ENGINE_POOL_TARGET_SIZE".into(), "32".into());
        let cfg = SupervisedPoolConfig::from_env(&env);
        assert!(!cfg.pool_initial_fraction_explicit);
        assert_eq!(cfg.pool_baseline, 4);
        assert_eq!(cfg.initial_session_count(), 4);
    }
}
