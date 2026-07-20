//! Ephemeral epoch rotation scheduling (port of `engine/epoch-rotation-policy.ts`).

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochRotationPolicy {
    pub rotation_interval_ms: u64,
    pub overlap_grace_ms: u64,
}

pub fn epoch_rotation_policy_from_env(env: &HashMap<String, String>) -> EpochRotationPolicy {
    let rotation_hours = env
        .get("TEECHAT_OPE_EPOCH_ROTATION_HOURS")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(24)
        .max(1);
    let overlap_minutes = env
        .get("TEECHAT_OPE_EPOCH_OVERLAP_GRACE_MIN")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(15)
        .max(1);
    EpochRotationPolicy {
        rotation_interval_ms: rotation_hours * 60 * 60 * 1000,
        overlap_grace_ms: overlap_minutes * 60 * 1000,
    }
}

pub fn epoch_rotation_lead_ms_from_env(env: &HashMap<String, String>) -> u64 {
    let lead_min = env
        .get("TEECHAT_OPE_EPOCH_ROTATION_LEAD_MIN")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(60)
        .max(1);
    lead_min * 60 * 1000
}

pub fn compute_epoch_rotate_at_ms(not_after_iso: &str, lead_ms: u64, now_ms: u64) -> u64 {
    let not_after_ms = crate::ops::parse_iso_time_ms(not_after_iso).unwrap_or(now_ms);
    now_ms.max(not_after_ms.saturating_sub(lead_ms))
}

pub fn epoch_ttl_ms_from_policy(policy: &EpochRotationPolicy) -> u64 {
    policy.rotation_interval_ms
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_rotation_policy_defaults() {
        let policy = epoch_rotation_policy_from_env(&HashMap::new());
        assert_eq!(policy.rotation_interval_ms, 24 * 60 * 60 * 1000);
        assert_eq!(policy.overlap_grace_ms, 15 * 60 * 1000);
    }
}
