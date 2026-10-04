//! Idle-time GPU evidence recollect (no client nonce).
//!
//! After boot, epoch rotation reuses last-good `gpu_tee.evidence` so live
//! `nvattest` never runs against a serving CUDA/GPU-CC context. This loop
//! optionally refreshes that cache when every pull worker is idle.
//!
//! Collector binding: `collect_nv_cc_gpu_evidence_b64(env, None)` — **not** a
//! client challenge nonce. Challenge freshness stays on nonce-bound SNP reports
//! that hash the cached GPU bytes (see `make_engine_challenge_handler`).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use ie_attestation::collect_nv_cc_gpu_evidence_b64;
use ie_protocol::AttestationBundle;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::sleep;

use crate::pool::SupervisedPool;
use crate::EpochRotator;

/// Shared last-good GPU evidence string (`AttestationBundle.gpu_tee.evidence`).
pub type GpuEvidenceCache = Arc<RwLock<String>>;

#[derive(Debug, Clone, Copy)]
pub struct GpuIdleRecollectConfig {
    /// How often to attempt a recollect when idle. `0` disables the loop.
    pub interval: Duration,
    /// Require this much continuous idle before calling `nvattest`.
    pub quiet: Duration,
}

impl GpuIdleRecollectConfig {
    /// `TEECHAT_GPU_EVIDENCE_IDLE_RECOLLECT_SECS` (default 21600 = 6h; `0` = off).
    /// `TEECHAT_GPU_EVIDENCE_IDLE_QUIET_SECS` (default 30).
    pub fn from_env(env: &HashMap<String, String>) -> Self {
        let interval_secs = env
            .get("TEECHAT_GPU_EVIDENCE_IDLE_RECOLLECT_SECS")
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(21_600);
        let quiet_secs = env
            .get("TEECHAT_GPU_EVIDENCE_IDLE_QUIET_SECS")
            .and_then(|s| s.trim().parse::<u64>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(30);
        Self {
            interval: Duration::from_secs(interval_secs),
            quiet: Duration::from_secs(quiet_secs),
        }
    }

    pub fn enabled(&self) -> bool {
        !self.interval.is_zero()
    }
}

pub fn new_gpu_evidence_cache(initial: impl Into<String>) -> GpuEvidenceCache {
    Arc::new(RwLock::new(initial.into()))
}

pub fn read_gpu_evidence_cache(cache: &GpuEvidenceCache) -> String {
    cache.read().expect("gpu evidence cache").clone()
}

pub fn write_gpu_evidence_cache(cache: &GpuEvidenceCache, evidence: String) {
    *cache.write().expect("gpu evidence cache") = evidence;
}

fn patch_bundle_gpu_evidence(mut bundle: AttestationBundle, evidence: String) -> AttestationBundle {
    bundle.gpu_tee.evidence = evidence;
    bundle
}

/// Spawn a background task that recollects GPU evidence only while the pool is idle.
///
/// Returns `None` when disabled via env. Failures leave the last-good cache unchanged.
pub fn spawn_gpu_evidence_idle_recollect(
    pool: Arc<SupervisedPool>,
    rotator: Arc<EpochRotator>,
    cache: GpuEvidenceCache,
    env: HashMap<String, String>,
    config: GpuIdleRecollectConfig,
    // Shared gate so concurrent idle collects cannot overlap.
    collect_gate: Arc<Mutex<()>>,
) -> Option<JoinHandle<()>> {
    if !config.enabled() {
        tracing::info!("gpu idle recollect disabled (interval=0)");
        return None;
    }
    tracing::info!(
        interval_secs = config.interval.as_secs(),
        quiet_secs = config.quiet.as_secs(),
        "gpu idle recollect armed"
    );
    Some(tokio::spawn(async move {
        // Stagger first attempt so boot / pool warm-up is not interrupted.
        sleep(config.interval).await;
        loop {
            if let Err(err) = wait_for_quiet_idle(&pool, config.quiet).await {
                tracing::debug!(error = %err, "gpu idle recollect wait interrupted");
                sleep(Duration::from_secs(30)).await;
                continue;
            }
            let gate = collect_gate.lock().await;
            if !pool.inference_idle().await {
                drop(gate);
                sleep(Duration::from_secs(5)).await;
                continue;
            }
            let env_c = env.clone();
            let collect = tokio::task::spawn_blocking(move || {
                // No client nonce. Optional SNP REPORT_DATA binding is only for
                // bundles minted together with a fresh report; idle refresh is
                // platform evidence only.
                collect_nv_cc_gpu_evidence_b64(&env_c, None)
            })
            .await;
            drop(gate);
            match collect {
                Ok(Ok(evidence)) => {
                    write_gpu_evidence_cache(&cache, evidence.clone());
                    if let Some(current) = rotator.current_attestation() {
                        rotator.set_attestation(patch_bundle_gpu_evidence(current, evidence));
                    }
                    tracing::info!("gpu idle recollect ok; last-good cache updated");
                }
                Ok(Err(err)) => {
                    tracing::warn!(
                        error = %err,
                        "gpu idle recollect failed; keeping last-good evidence"
                    );
                }
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        "gpu idle recollect join failed; keeping last-good evidence"
                    );
                }
            }
            sleep(config.interval).await;
        }
    }))
}

async fn wait_for_quiet_idle(pool: &SupervisedPool, quiet: Duration) -> Result<(), &'static str> {
    let mut idle_since: Option<std::time::Instant> = None;
    loop {
        if pool.inference_idle().await {
            let since = *idle_since.get_or_insert_with(std::time::Instant::now);
            if since.elapsed() >= quiet {
                return Ok(());
            }
        } else {
            idle_since = None;
        }
        sleep(Duration::from_secs(5)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_and_disable() {
        let cfg = GpuIdleRecollectConfig::from_env(&HashMap::new());
        assert_eq!(cfg.interval.as_secs(), 21_600);
        assert_eq!(cfg.quiet.as_secs(), 30);
        assert!(cfg.enabled());

        let off = GpuIdleRecollectConfig::from_env(&HashMap::from([(
            "TEECHAT_GPU_EVIDENCE_IDLE_RECOLLECT_SECS".into(),
            "0".into(),
        )]));
        assert!(!off.enabled());
    }

    #[test]
    fn cache_roundtrip() {
        let cache = new_gpu_evidence_cache("boot");
        assert_eq!(read_gpu_evidence_cache(&cache), "boot");
        write_gpu_evidence_cache(&cache, "idle".into());
        assert_eq!(read_gpu_evidence_cache(&cache), "idle");
    }
}
