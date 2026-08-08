//! Phase 2a attested ops-control (gateway → engine via work-pull).
//!
//! Narrow verbs only: force_target / drain / migrate / status.
//! Invokes [`SupervisedPool`] APIs directly (no SIGUSR / control files).

use std::sync::Arc;
use std::time::{Duration, Instant};

use ie_protocol::{EngineOpsControlOp, EngineOpsControlRequest, EngineOpsControlResult};
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::desired_pool::apply_desired_pool_target;
use crate::pool::SupervisedPool;

/// Validate ops-control request shape before touching the pool.
pub fn validate_ops_control_request(req: &EngineOpsControlRequest) -> Result<(), &'static str> {
    match req.op {
        EngineOpsControlOp::ForceTarget => {
            let Some(n) = req.target_size else {
                return Err("target_size_required");
            };
            if n == 0 {
                return Err("target_size_invalid");
            }
            Ok(())
        }
        EngineOpsControlOp::Drain => {
            match (req.drain_count, req.drain_fraction) {
                (Some(c), None) if c > 0 => Ok(()),
                (None, Some(f)) if (0.0..=1.0).contains(&f) => Ok(()),
                (Some(_), Some(_)) => Err("drain_count_and_fraction_exclusive"),
                _ => Err("drain_fraction_or_count_required"),
            }
        }
        EngineOpsControlOp::Migrate => {
            let url = req.migrate_url.as_deref().unwrap_or("").trim();
            if url.is_empty() {
                return Err("migrate_url_required");
            }
            if req.confirm != Some(true) {
                return Err("migrate_confirm_required");
            }
            if let Some(f) = req.migrate_fraction {
                if !(0.0..=1.0).contains(&f) {
                    return Err("migrate_fraction_invalid");
                }
            }
            Ok(())
        }
        EngineOpsControlOp::Status => Ok(()),
    }
}

/// Apply a validated ops-control request against the live supervised pool.
pub async fn apply_engine_ops_control(
    pool: &Arc<SupervisedPool>,
    engine_id: &str,
    req: EngineOpsControlRequest,
) -> EngineOpsControlResult {
    if let Err(error) = validate_ops_control_request(&req) {
        return EngineOpsControlResult {
            ok: false,
            op: req.op,
            engine_id: engine_id.to_string(),
            pool_target: None,
            live_sessions: Some(pool.live_session_count().await),
            draining: None,
            detail: None,
            error: Some(error.to_string()),
        };
    }

    let result = match req.op {
        EngineOpsControlOp::ForceTarget => {
            let target = req.target_size.expect("validated");
            match apply_desired_pool_target(pool, pool.config(), target).await {
                Ok(()) => {
                    let live = pool.live_session_count().await;
                    info!(engine_id, target, live, "ops_control force_target applied");
                    EngineOpsControlResult {
                        ok: true,
                        op: req.op,
                        engine_id: engine_id.to_string(),
                        pool_target: Some(target),
                        live_sessions: Some(live),
                        draining: None,
                        detail: Some(format!("forced_to_{target}")),
                        error: None,
                    }
                }
                Err(e) => EngineOpsControlResult {
                    ok: false,
                    op: req.op,
                    engine_id: engine_id.to_string(),
                    pool_target: Some(target),
                    live_sessions: Some(pool.live_session_count().await),
                    draining: None,
                    detail: None,
                    error: Some(e.to_string()),
                },
            }
        }
        EngineOpsControlOp::Drain => {
            let drain_res = if let Some(count) = req.drain_count {
                pool.drain_idle_sessions(count).await
            } else {
                pool.drain_idle_pool(req.drain_fraction.expect("validated"))
                    .await
            };
            match drain_res {
                Ok(r) => {
                    info!(
                        engine_id,
                        drained = r.drained,
                        remaining = r.remaining,
                        blocked = r.blocked,
                        "ops_control drain applied"
                    );
                    EngineOpsControlResult {
                        ok: !r.blocked || r.drained > 0,
                        op: req.op,
                        engine_id: engine_id.to_string(),
                        pool_target: None,
                        live_sessions: Some(r.remaining),
                        draining: Some(r.drained),
                        detail: r.reason,
                        error: if r.blocked && r.drained == 0 {
                            Some("drain_blocked".into())
                        } else {
                            None
                        },
                    }
                }
                Err(e) => EngineOpsControlResult {
                    ok: false,
                    op: req.op,
                    engine_id: engine_id.to_string(),
                    pool_target: None,
                    live_sessions: Some(pool.live_session_count().await),
                    draining: None,
                    detail: None,
                    error: Some(e.to_string()),
                },
            }
        }
        EngineOpsControlOp::Migrate => {
            let url = req.migrate_url.as_deref().unwrap_or("").trim();
            let fraction = req.migrate_fraction.unwrap_or(1.0);
            match pool.migrate_gateway_pool(url, fraction).await {
                Ok(r) => {
                    info!(
                        engine_id,
                        moved = r.moved,
                        on_target = r.on_target,
                        blocked = r.blocked,
                        "ops_control migrate applied"
                    );
                    EngineOpsControlResult {
                        ok: !r.blocked || r.moved > 0,
                        op: req.op,
                        engine_id: engine_id.to_string(),
                        pool_target: None,
                        live_sessions: Some(r.on_source + r.on_target),
                        draining: None,
                        detail: r.reason.or_else(|| Some(format!("moved_{}", r.moved))),
                        error: if r.blocked && r.moved == 0 {
                            Some("migrate_blocked".into())
                        } else {
                            None
                        },
                    }
                }
                Err(e) => EngineOpsControlResult {
                    ok: false,
                    op: req.op,
                    engine_id: engine_id.to_string(),
                    pool_target: None,
                    live_sessions: Some(pool.live_session_count().await),
                    draining: None,
                    detail: None,
                    error: Some(e.to_string()),
                },
            }
        }
        EngineOpsControlOp::Status => {
            let live = pool.live_session_count().await;
            let pool_target = pool
                .connect_template()
                .await
                .and_then(|t| t.pool_target_size)
                .or(Some(pool.config().pool_target_size));
            EngineOpsControlResult {
                ok: true,
                op: req.op,
                engine_id: engine_id.to_string(),
                pool_target,
                live_sessions: Some(live),
                draining: None,
                detail: None,
                error: None,
            }
        }
    };

    if !result.ok {
        warn!(
            engine_id,
            op = ?req.op,
            error = ?result.error,
            "ops_control failed"
        );
    }
    result
}

/// Simple sliding-window rate limit for force_target / drain (gateway also limits).
pub struct OpsControlRateLimiter {
    window: Duration,
    max_hits: usize,
    hits: Mutex<Vec<Instant>>,
}

impl OpsControlRateLimiter {
    pub fn new(window: Duration, max_hits: usize) -> Self {
        Self {
            window,
            max_hits: max_hits.max(1),
            hits: Mutex::new(Vec::new()),
        }
    }

    pub fn default_prod() -> Self {
        Self::new(Duration::from_secs(60), 30)
    }

    pub async fn check(&self, op: EngineOpsControlOp) -> Result<(), &'static str> {
        match op {
            EngineOpsControlOp::ForceTarget | EngineOpsControlOp::Drain => {}
            EngineOpsControlOp::Migrate | EngineOpsControlOp::Status => return Ok(()),
        }
        let mut hits = self.hits.lock().await;
        let now = Instant::now();
        hits.retain(|t| now.duration_since(*t) <= self.window);
        if hits.len() >= self.max_hits {
            return Err("rate_limited");
        }
        hits.push(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_force_target() {
        assert!(validate_ops_control_request(&EngineOpsControlRequest {
            op: EngineOpsControlOp::ForceTarget,
            target_size: Some(8),
            drain_fraction: None,
            drain_count: None,
            migrate_url: None,
            migrate_fraction: None,
            confirm: None,
        })
        .is_ok());
        assert_eq!(
            validate_ops_control_request(&EngineOpsControlRequest {
                op: EngineOpsControlOp::ForceTarget,
                target_size: None,
                drain_fraction: None,
                drain_count: None,
                migrate_url: None,
                migrate_fraction: None,
                confirm: None,
            })
            .unwrap_err(),
            "target_size_required"
        );
        assert_eq!(
            validate_ops_control_request(&EngineOpsControlRequest {
                op: EngineOpsControlOp::ForceTarget,
                target_size: Some(0),
                drain_fraction: None,
                drain_count: None,
                migrate_url: None,
                migrate_fraction: None,
                confirm: None,
            })
            .unwrap_err(),
            "target_size_invalid"
        );
    }

    #[test]
    fn validate_drain() {
        assert!(validate_ops_control_request(&EngineOpsControlRequest {
            op: EngineOpsControlOp::Drain,
            target_size: None,
            drain_fraction: Some(0.5),
            drain_count: None,
            migrate_url: None,
            migrate_fraction: None,
            confirm: None,
        })
        .is_ok());
        assert!(validate_ops_control_request(&EngineOpsControlRequest {
            op: EngineOpsControlOp::Drain,
            target_size: None,
            drain_fraction: None,
            drain_count: Some(2),
            migrate_url: None,
            migrate_fraction: None,
            confirm: None,
        })
        .is_ok());
        assert_eq!(
            validate_ops_control_request(&EngineOpsControlRequest {
                op: EngineOpsControlOp::Drain,
                target_size: None,
                drain_fraction: Some(0.5),
                drain_count: Some(1),
                migrate_url: None,
                migrate_fraction: None,
                confirm: None,
            })
            .unwrap_err(),
            "drain_count_and_fraction_exclusive"
        );
    }

    #[test]
    fn validate_migrate_requires_confirm() {
        assert_eq!(
            validate_ops_control_request(&EngineOpsControlRequest {
                op: EngineOpsControlOp::Migrate,
                target_size: None,
                drain_fraction: None,
                drain_count: None,
                migrate_url: Some("https://gw.example".into()),
                migrate_fraction: Some(1.0),
                confirm: None,
            })
            .unwrap_err(),
            "migrate_confirm_required"
        );
        assert!(validate_ops_control_request(&EngineOpsControlRequest {
            op: EngineOpsControlOp::Migrate,
            target_size: None,
            drain_fraction: None,
            drain_count: None,
            migrate_url: Some("https://gw.example".into()),
            migrate_fraction: Some(1.0),
            confirm: Some(true),
        })
        .is_ok());
    }

    #[tokio::test]
    async fn rate_limiter_trips_on_force_target() {
        let lim = OpsControlRateLimiter::new(Duration::from_secs(60), 2);
        assert!(lim.check(EngineOpsControlOp::ForceTarget).await.is_ok());
        assert!(lim.check(EngineOpsControlOp::Drain).await.is_ok());
        assert_eq!(
            lim.check(EngineOpsControlOp::ForceTarget).await.unwrap_err(),
            "rate_limited"
        );
        // status/migrate are not rate-limited by this gate
        assert!(lim.check(EngineOpsControlOp::Status).await.is_ok());
    }

    // --- apply_engine_ops_control against a stub supervised pool ---

    use async_trait::async_trait;
    use ie_protocol::{
        AttestationBundle, AttestationVerdict, AttestedConnectRequest, AttestedConnectResponse,
        CpuTeeAttestation, CpuTeeKind, EngineStartupIdentity, GpuTeeAttestation, GpuTeeKind,
        WorkloadMeasurements,
    };
    use std::sync::atomic::{AtomicU32, Ordering};

    use crate::config::{PoolReconnectConfig, SupervisedPoolConfig};
    use crate::cutover::PoolConnectThrottle;
    use crate::traits::{ConnectResult, EnginePlaneConnector, InferResult, InferenceUpstream};

    static NEXT_ID: AtomicU32 = AtomicU32::new(1);

    struct MockConnector;
    #[async_trait]
    impl EnginePlaneConnector for MockConnector {
        async fn connect(
            &self,
            request: AttestedConnectRequest,
        ) -> Result<ConnectResult, Box<dyn std::error::Error + Send + Sync>> {
            let sid = if request.session_id.is_empty() {
                format!("sess-{}", NEXT_ID.fetch_add(1, Ordering::SeqCst))
            } else {
                format!(
                    "{}-{}",
                    request.session_id,
                    NEXT_ID.fetch_add(1, Ordering::SeqCst)
                )
            };
            Ok(ConnectResult {
                session_id: sid,
                response: AttestedConnectResponse {
                    ok: true,
                    gateway_attestation: None,
                    pool_target_ack: Some(1),
                    gateway_challenge_nonce: None,
                },
            })
        }

        async fn disconnect(
            &self,
            _session_id: &str,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
    }

    struct MockUpstream;
    #[async_trait]
    impl InferenceUpstream for MockUpstream {
        async fn infer_chat(
            &self,
            _model: &str,
            prompt: &str,
        ) -> Result<InferResult, Box<dyn std::error::Error + Send + Sync>> {
            Ok(InferResult {
                completion: format!("echo:{prompt}"),
                finish_reason: Some("stop".into()),
            })
        }
    }

    fn sample_request() -> AttestedConnectRequest {
        AttestedConnectRequest {
            session_id: "sess".into(),
            engine_id: "eng-1".into(),
            models: vec!["m".into()],
            identity: EngineStartupIdentity {
                engine_id: "eng-1".into(),
                kex: "kex".into(),
                ed25519_public: "pk".into(),
            },
            attestation: AttestationBundle {
                cpu_tee: CpuTeeAttestation {
                    kind: CpuTeeKind::SevSnp,
                    quote: "q".into(),
                    verdict: AttestationVerdict::Pass,
                    policy_id: "p".into(),
                    endorsement: None,
                },
                gpu_tee: GpuTeeAttestation {
                    kind: GpuTeeKind::NvCc,
                    evidence: "g".into(),
                    verdict: AttestationVerdict::Pass,
                },
                vllm: WorkloadMeasurements {
                    version: "v".into(),
                    binary_sha256: "b".into(),
                },
                engine: WorkloadMeasurements {
                    version: "e".into(),
                    binary_sha256: "c".into(),
                },
                ope: None,
                attested_mtls: None,
            },
            pool_target_size: Some(4),
            instance_id: None,
            gateway_challenge_nonce: None,
            capabilities: Some(vec!["ops_control_v1".into()]),
        }
    }

    fn test_pool() -> Arc<SupervisedPool> {
        let config = SupervisedPoolConfig {
            pool_target_size: 4,
            pool_initial_fraction: 1.0,
            pool_initial_fraction_explicit: true,
            pool_baseline: 1,
            supervised: true,
            reconnect: PoolReconnectConfig::default(),
        };
        Arc::new(
            SupervisedPool::new(
                config,
                "https://gateway.example",
                Arc::new(MockConnector),
                Arc::new(MockUpstream),
            )
            .with_connect_throttle(PoolConnectThrottle::new(8, 0)),
        )
    }

    #[tokio::test]
    async fn apply_status_and_force_target_and_drain() {
        let pool = test_pool();
        pool.boot(sample_request()).await.unwrap();
        assert_eq!(pool.live_session_count().await, 4);

        let status = apply_engine_ops_control(
            &pool,
            "eng-1",
            EngineOpsControlRequest {
                op: EngineOpsControlOp::Status,
                target_size: None,
                drain_fraction: None,
                drain_count: None,
                migrate_url: None,
                migrate_fraction: None,
                confirm: None,
            },
        )
        .await;
        assert!(status.ok);
        assert_eq!(status.live_sessions, Some(4));
        assert_eq!(status.pool_target, Some(4));

        let forced = apply_engine_ops_control(
            &pool,
            "eng-1",
            EngineOpsControlRequest {
                op: EngineOpsControlOp::ForceTarget,
                target_size: Some(2),
                drain_fraction: None,
                drain_count: None,
                migrate_url: None,
                migrate_fraction: None,
                confirm: None,
            },
        )
        .await;
        assert!(forced.ok, "{forced:?}");
        assert_eq!(forced.live_sessions, Some(2));

        let drained = apply_engine_ops_control(
            &pool,
            "eng-1",
            EngineOpsControlRequest {
                op: EngineOpsControlOp::Drain,
                target_size: None,
                drain_fraction: None,
                drain_count: Some(1),
                migrate_url: None,
                migrate_fraction: None,
                confirm: None,
            },
        )
        .await;
        assert!(drained.ok || drained.draining == Some(0), "{drained:?}");
        assert!(drained.live_sessions.unwrap_or(0) <= 2);

        let bad = apply_engine_ops_control(
            &pool,
            "eng-1",
            EngineOpsControlRequest {
                op: EngineOpsControlOp::Migrate,
                target_size: None,
                drain_fraction: None,
                drain_count: None,
                migrate_url: Some("https://other".into()),
                migrate_fraction: Some(1.0),
                confirm: None,
            },
        )
        .await;
        assert!(!bad.ok);
        assert_eq!(bad.error.as_deref(), Some("migrate_confirm_required"));
    }
}
