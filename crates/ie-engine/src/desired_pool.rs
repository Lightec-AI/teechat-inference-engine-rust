//! Gateway `x-ope-desired-pool-target` hint → scale / idle-drain (TS supervised-pool parity).

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::config::SupervisedPoolConfig;
use crate::error::EngineError;
use crate::pool::SupervisedPool;

/// Wire header (ope-protocol); defined locally until git ope-protocol rev includes it.
pub const HEADER_OPE_DESIRED_POOL_TARGET: &str = "x-ope-desired-pool-target";

pub const DESIRED_POOL_DEBOUNCE_MS: u64 = 2_000;

pub type DesiredPoolTargetCallback = Arc<dyn Fn(u32) + Send + Sync>;

pub fn parse_desired_pool_target_header(raw: Option<&str>) -> Option<u32> {
    let value = raw?.trim();
    if value.is_empty() {
        return None;
    }
    let n: u32 = value.parse().ok()?;
    if n < 1 {
        None
    } else {
        Some(n)
    }
}

pub fn clamp_desired_pool_target(raw: u32, baseline: u32, max: u32) -> u32 {
    let lo = baseline.min(max);
    let hi = baseline.max(max);
    raw.clamp(lo, hi)
}

/// Apply a gateway desired target once (no debounce).
pub async fn apply_desired_pool_target(
    pool: &Arc<SupervisedPool>,
    config: &SupervisedPoolConfig,
    raw_desired: u32,
) -> Result<(), EngineError> {
    let desired = clamp_desired_pool_target(raw_desired, config.pool_baseline, config.pool_target_size);
    let current = pool.live_session_count().await;
    if desired == current {
        return Ok(());
    }
    if desired > current {
        let template = pool
            .connect_template()
            .await
            .ok_or_else(|| EngineError::Scale("no connect template; boot pool before scale".into()))?;
        let added = pool.scale_to(desired, template).await?;
        info!(desired, current, added, "desired pool target scale-up");
        return Ok(());
    }
    let to_drain = current - desired;
    let result = pool.drain_idle_sessions(to_drain).await?;
    info!(
        desired,
        current,
        drained = result.drained,
        remaining = result.remaining,
        "desired pool target idle-drain"
    );
    Ok(())
}

/// Spawn a debounced applier. Pull workers are started/stopped by the pool itself.
pub fn spawn_desired_pool_applier(
    pool: Arc<SupervisedPool>,
    config: SupervisedPoolConfig,
) -> DesiredPoolTargetCallback {
    let (tx, mut rx) = mpsc::unbounded_channel::<u32>();
    tokio::spawn(async move {
        loop {
            let Some(first) = rx.recv().await else {
                break;
            };
            let mut pending = first;
            // Debounce: wait, then drain coalesced hints.
            tokio::time::sleep(Duration::from_millis(DESIRED_POOL_DEBOUNCE_MS)).await;
            while let Ok(more) = rx.try_recv() {
                pending = more;
            }
            if let Err(err) = apply_desired_pool_target(&pool, &config, pending).await {
                warn!(error = %err, desired = pending, "desired pool apply failed");
            }
        }
    });

    Arc::new(move |n: u32| {
        let _ = tx.send(n);
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_header() {
        assert_eq!(parse_desired_pool_target_header(Some("12")), Some(12));
        assert_eq!(parse_desired_pool_target_header(Some("0")), None);
        assert_eq!(parse_desired_pool_target_header(Some("nope")), None);
        assert_eq!(parse_desired_pool_target_header(None), None);
    }

    #[test]
    fn clamps_to_baseline_max() {
        assert_eq!(clamp_desired_pool_target(1, 4, 32), 4);
        assert_eq!(clamp_desired_pool_target(40, 4, 32), 32);
        assert_eq!(clamp_desired_pool_target(12, 4, 32), 12);
    }
}
