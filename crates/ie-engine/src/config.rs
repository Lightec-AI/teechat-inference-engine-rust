use std::collections::HashMap;

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
    pub pool_initial_fraction: f64,
    pub supervised: bool,
    pub reconnect: PoolReconnectConfig,
}

impl SupervisedPoolConfig {
    pub fn from_env(env: &HashMap<String, String>) -> Self {
        let pool_target_size = env
            .get("TEECHAT_ENGINE_POOL_TARGET_SIZE")
            .and_then(|v| v.parse().ok())
            .unwrap_or(1)
            .max(1);
        let pool_initial_fraction: f64 = env
            .get("TEECHAT_ENGINE_POOL_INITIAL_FRACTION")
            .and_then(|v| v.parse().ok())
            .unwrap_or(1.0);
        let pool_initial_fraction = pool_initial_fraction.clamp(0.0, 1.0);
        let supervised = !env
            .get("TEECHAT_ENGINE_SUPERVISED")
            .map(|v| v.eq_ignore_ascii_case("false") || v == "0")
            .unwrap_or(false);
        Self {
            pool_target_size,
            pool_initial_fraction,
            supervised,
            reconnect: PoolReconnectConfig::from_env(env),
        }
    }

    pub fn initial_session_count(&self) -> u32 {
        ((self.pool_target_size as f64) * self.pool_initial_fraction)
            .floor()
            .max(1.0) as u32
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
            supervised: true,
            reconnect: PoolReconnectConfig::default(),
        };
        assert_eq!(cfg.initial_session_count(), 2);
    }
}
