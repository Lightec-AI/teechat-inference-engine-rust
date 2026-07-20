//! Idle-first pool drain/scale planning (port of `engine/pool-cutover.ts`).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Deserialize;
use tokio::sync::Semaphore;
use tokio::time::sleep;

pub const DEFAULT_POOL_CONNECT_CONCURRENCY: u32 = 2;
pub const DEFAULT_POOL_CONNECT_STAGGER_MS: u64 = 150;

#[derive(Debug, Clone, PartialEq)]
pub struct PoolDrainPlan {
    pub target_remaining: u32,
    pub to_drain: u32,
    pub blocked: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PoolScalePlan {
    pub target_size: u32,
    pub to_add: u32,
    pub blocked: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PoolDrainRequest {
    #[serde(default)]
    pub fraction: Option<f64>,
    #[serde(default)]
    pub count: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PoolScaleRequest {
    #[serde(alias = "targetSize")]
    pub target_size: u32,
}

pub fn initial_pool_session_count(pool_target_size: u32, fraction: f64) -> u32 {
    if pool_target_size < 1 {
        return 0;
    }
    if fraction <= 0.0 {
        return 0;
    }
    if fraction >= 1.0 {
        return pool_target_size;
    }
    ((pool_target_size as f64) * fraction).floor().max(1.0) as u32
}

pub fn plan_pool_drain_by_count(current_count: u32, count: u32, idle_count: u32) -> PoolDrainPlan {
    if current_count < 1 {
        return PoolDrainPlan {
            target_remaining: 0,
            to_drain: 0,
            blocked: false,
            reason: None,
        };
    }
    if count < 1 {
        return PoolDrainPlan {
            target_remaining: current_count,
            to_drain: 0,
            blocked: true,
            reason: Some("invalid_count".into()),
        };
    }
    let want_drain = count.min(current_count);
    let to_drain = want_drain.min(idle_count);
    let blocked = to_drain < want_drain;
    PoolDrainPlan {
        target_remaining: current_count - to_drain,
        to_drain,
        blocked,
        reason: blocked.then_some("insufficient_idle_sessions".into()),
    }
}

pub fn plan_pool_drain(
    pool_target_size: u32,
    current_count: u32,
    fraction: Option<f64>,
    count: Option<u32>,
    idle_count: u32,
) -> PoolDrainPlan {
    if let Some(c) = count {
        return plan_pool_drain_by_count(current_count, c, idle_count);
    }
    if current_count < 1 {
        return PoolDrainPlan {
            target_remaining: 0,
            to_drain: 0,
            blocked: false,
            reason: None,
        };
    }
    if pool_target_size < 1 {
        return PoolDrainPlan {
            target_remaining: current_count,
            to_drain: 0,
            blocked: true,
            reason: Some("pool_size_zero".into()),
        };
    }
    let fraction = fraction.unwrap_or(-1.0);
    if !(0.0..=1.0).contains(&fraction) {
        return PoolDrainPlan {
            target_remaining: current_count,
            to_drain: 0,
            blocked: true,
            reason: Some("invalid_fraction".into()),
        };
    }
    let target_remaining = ((pool_target_size as f64) * (1.0 - fraction)).floor() as u32;
    let want_drain = current_count.saturating_sub(target_remaining);
    if want_drain == 0 {
        return PoolDrainPlan {
            target_remaining: current_count,
            to_drain: 0,
            blocked: false,
            reason: None,
        };
    }
    let to_drain = want_drain.min(idle_count);
    let blocked = to_drain < want_drain;
    PoolDrainPlan {
        target_remaining: current_count - to_drain,
        to_drain,
        blocked,
        reason: blocked.then_some("insufficient_idle_sessions".into()),
    }
}

pub fn plan_pool_scale(pool_target_size: u32, current_count: u32, target_size: u32) -> PoolScalePlan {
    if pool_target_size < 1 {
        return PoolScalePlan {
            target_size,
            to_add: 0,
            blocked: true,
            reason: Some("pool_size_zero".into()),
        };
    }
    if target_size < 1 || target_size > pool_target_size {
        return PoolScalePlan {
            target_size,
            to_add: 0,
            blocked: true,
            reason: Some("invalid_target_size".into()),
        };
    }
    PoolScalePlan {
        target_size,
        to_add: target_size.saturating_sub(current_count),
        blocked: false,
        reason: None,
    }
}

pub fn parse_pool_drain_request_json(raw: &str) -> Result<PoolDrainRequest, String> {
    let parsed: PoolDrainRequest = serde_json::from_str(raw).map_err(|e| e.to_string())?;
    if let Some(count) = parsed.count {
        if count < 1 {
            return Err("pool drain: count must be a positive integer".into());
        }
        return Ok(PoolDrainRequest {
            fraction: None,
            count: Some(count),
        });
    }
    let fraction = parsed.fraction.ok_or_else(|| {
        "pool drain: require fraction (0..1) or count (>=1)".to_string()
    })?;
    if !(0.0..=1.0).contains(&fraction) {
        return Err("pool drain: fraction must be 0..1".into());
    }
    Ok(PoolDrainRequest {
        fraction: Some(fraction),
        count: None,
    })
}

pub fn parse_pool_scale_request_json(raw: &str) -> Result<PoolScaleRequest, String> {
    let parsed: PoolScaleRequest = serde_json::from_str(raw).map_err(|e| e.to_string())?;
    if parsed.target_size < 1 {
        return Err("pool scale: target_size must be a positive integer".into());
    }
    Ok(parsed)
}

pub fn pool_initial_fraction_from_env(env: &HashMap<String, String>) -> f64 {
    let raw = env
        .get("TEECHAT_ENGINE_POOL_INITIAL_FRACTION")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());
    let Some(raw) = raw else {
        return 1.0;
    };
    let Ok(n) = raw.parse::<f64>() else {
        return 1.0;
    };
    if !(0.0..=1.0).contains(&n) {
        1.0
    } else {
        n
    }
}

pub fn pool_connect_concurrency_from_env(env: &HashMap<String, String>, session_count: u32) -> u32 {
    if session_count < 1 {
        return 1;
    }
    let raw = env
        .get("TEECHAT_ENGINE_POOL_CONNECT_CONCURRENCY")
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty());
    if raw.as_deref() == Some("0") || raw.as_deref() == Some("unlimited") {
        return session_count;
    }
    let n = raw
        .and_then(|s| s.parse::<u32>().ok())
        .filter(|&n| n >= 1)
        .unwrap_or(DEFAULT_POOL_CONNECT_CONCURRENCY);
    n.min(session_count)
}

pub fn pool_connect_stagger_ms_from_env(env: &HashMap<String, String>) -> u64 {
    let raw = env
        .get("TEECHAT_ENGINE_POOL_CONNECT_STAGGER_MS")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());
    let Some(raw) = raw else {
        return DEFAULT_POOL_CONNECT_STAGGER_MS;
    };
    if raw == "0" {
        return 0;
    }
    raw.parse::<u64>()
        .ok()
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_POOL_CONNECT_STAGGER_MS)
}

pub struct PoolConnectThrottle {
    semaphore: Arc<Semaphore>,
    stagger_ms: u64,
    next_start: tokio::sync::Mutex<Instant>,
}

impl PoolConnectThrottle {
    pub fn new(concurrency: u32, stagger_ms: u64) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(concurrency.max(1) as usize)),
            stagger_ms,
            next_start: tokio::sync::Mutex::new(Instant::now()),
        }
    }

    pub async fn run<F, Fut, T>(&self, f: F) -> T
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        let _permit = self.semaphore.acquire().await.expect("semaphore");
        let wait = {
            let mut next = self.next_start.lock().await;
            let now = Instant::now();
            let wait = next.saturating_duration_since(now);
            *next = now.max(*next) + Duration::from_millis(self.stagger_ms);
            wait
        };
        if !wait.is_zero() {
            sleep(wait).await;
        }
        f().await
    }
}

pub fn create_pool_connect_throttle_from_env(
    env: &HashMap<String, String>,
    session_count_hint: u32,
) -> PoolConnectThrottle {
    PoolConnectThrottle::new(
        pool_connect_concurrency_from_env(env, session_count_hint),
        pool_connect_stagger_ms_from_env(env),
    )
}

pub async fn map_with_concurrency<F, Fut, T>(count: u32, concurrency: u32, f: F) -> Vec<T>
where
    F: Fn(u32) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = T> + Send,
    T: Send + 'static,
{
    if count == 0 {
        return Vec::new();
    }
    let limit = concurrency.max(1).min(count) as usize;
    let f = Arc::new(f);
    let mut handles = Vec::with_capacity(limit);
    let chunk = (count as usize).div_ceil(limit);
    for worker in 0..limit {
        let start = worker * chunk;
        if start >= count as usize {
            break;
        }
        let end = (start + chunk).min(count as usize);
        let f = Arc::clone(&f);
        handles.push(tokio::spawn(async move {
            let mut out = Vec::with_capacity(end - start);
            for index in start..end {
                out.push(f(index as u32).await);
            }
            out
        }));
    }
    let mut results = Vec::with_capacity(count as usize);
    for handle in handles {
        results.extend(handle.await.expect("task"));
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_pool_session_count_halves_n4() {
        assert_eq!(initial_pool_session_count(4, 0.5), 2);
    }

    #[test]
    fn plan_pool_drain_half_of_two() {
        let plan = plan_pool_drain(2, 2, Some(0.5), None, 2);
        assert_eq!(plan.to_drain, 1);
        assert!(!plan.blocked);
    }

    #[test]
    fn parse_pool_scale_request_json_works() {
        let req = parse_pool_scale_request_json(r#"{"target_size":2}"#).unwrap();
        assert_eq!(req.target_size, 2);
    }

    #[tokio::test]
    async fn map_with_concurrency_preserves_order() {
        let out = map_with_concurrency(4, 2, |i| async move { i * 2 }).await;
        assert_eq!(out, vec![0, 2, 4, 6]);
    }
}
