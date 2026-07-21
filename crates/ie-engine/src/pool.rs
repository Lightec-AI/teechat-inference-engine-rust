use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;
use tracing::{info, warn};

use ie_protocol::{AttestationBundle, AttestedConnectRequest};

use crate::config::SupervisedPoolConfig;
use crate::cutover::{plan_pool_drain, plan_pool_scale};
use crate::error::EngineError;
use crate::gateway_migration::plan_gateway_migration;
use crate::pull_workers::{
    warn_pull_worker_start, PullWorkerRegistry, PullWorkerStartFn, SessionsChangedFn,
};
use crate::traits::{ConnectResult, EnginePlaneConnector, InferenceUpstream, InferResult};

/// Remint attestation before reconnect / scale / migrate (optional).
pub type AttestationRefreshFn =
    Arc<dyn Fn() -> Result<AttestationBundle, String> + Send + Sync>;

#[derive(Debug, Clone)]
pub struct PoolSession {
    pub session_id: String,
    pub gateway_base_url: String,
}

struct SessionSlot {
    session: PoolSession,
    busy: AtomicBool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayMigrationResult {
    pub moved: u32,
    pub on_target: u32,
    pub on_source: u32,
    pub target_count: u32,
    pub blocked: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolDrainResult {
    pub drained: u32,
    pub remaining: u32,
    pub target_remaining: u32,
    pub blocked: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolScaleResult {
    pub added: u32,
    pub total: u32,
    pub target_size: u32,
    pub blocked: bool,
    pub reason: Option<String>,
}

#[derive(Default)]
struct PoolState {
    slots: Vec<SessionSlot>,
    consecutive_failures: u32,
    circuit_open_until_ms: u64,
}

impl Default for SessionSlot {
    fn default() -> Self {
        Self {
            session: PoolSession {
                session_id: String::new(),
                gateway_base_url: String::new(),
            },
            busy: AtomicBool::new(false),
        }
    }
}

pub struct SupervisedPool {
    config: SupervisedPoolConfig,
    gateway_base_url: RwLock<String>,
    connector: Arc<dyn EnginePlaneConnector>,
    upstream: Arc<dyn InferenceUpstream>,
    /// Last successful connect template (used by scale / migrate).
    connect_template: RwLock<Option<AttestedConnectRequest>>,
    /// Optional remint hook (parity with TS `applyFreshAttestation`).
    attestation_refresh: RwLock<Option<AttestationRefreshFn>>,
    /// Pull workers owned like TS `SessionSlot.pullWorker`.
    workers: PullWorkerRegistry,
    /// Notify epoch rotator / ops when live session ids change.
    on_sessions_changed: RwLock<Option<SessionsChangedFn>>,
    state: RwLock<PoolState>,
}

pub struct SupervisedPoolHandle {
    pool: Arc<SupervisedPool>,
}

impl SupervisedPool {
    pub fn new(
        config: SupervisedPoolConfig,
        gateway_base_url: impl Into<String>,
        connector: Arc<dyn EnginePlaneConnector>,
        upstream: Arc<dyn InferenceUpstream>,
    ) -> Self {
        Self {
            config,
            gateway_base_url: RwLock::new(gateway_base_url.into()),
            connector,
            upstream,
            connect_template: RwLock::new(None),
            attestation_refresh: RwLock::new(None),
            workers: PullWorkerRegistry::new(),
            on_sessions_changed: RwLock::new(None),
            state: RwLock::new(PoolState::default()),
        }
    }

    /// Install / replace attestation remint used on scale + migrate (+ reconnect paths).
    pub async fn set_attestation_refresh(&self, refresh: Option<AttestationRefreshFn>) {
        *self.attestation_refresh.write().await = refresh;
    }

    /// Register pull-worker factory (required for live H2; unit tests leave unset).
    pub async fn set_pull_worker_start_fn(&self, start_fn: Option<PullWorkerStartFn>) {
        self.workers.set_start_fn(start_fn).await;
    }

    pub async fn set_on_sessions_changed(&self, cb: Option<SessionsChangedFn>) {
        *self.on_sessions_changed.write().await = cb;
    }

    pub fn workers(&self) -> &PullWorkerRegistry {
        &self.workers
    }

    async fn notify_sessions_changed(&self) {
        let ids = self.session_ids().await;
        if let Some(cb) = self.on_sessions_changed.read().await.clone() {
            cb(ids);
        }
    }

    /// Busy = live pull worker busy (TS), else slot flag (tests without workers).
    async fn session_is_busy(&self, session_id: &str) -> bool {
        if self.workers.has_worker(session_id).await {
            return self.workers.is_busy(session_id).await;
        }
        let state = self.state.read().await;
        state
            .slots
            .iter()
            .find(|s| s.session.session_id == session_id)
            .map(|s| s.busy.load(Ordering::SeqCst))
            .unwrap_or(false)
    }

    async fn idle_session_ids(&self) -> Vec<String> {
        let ids = self.session_ids().await;
        let mut idle = Vec::new();
        for id in ids {
            if !self.session_is_busy(&id).await {
                idle.push(id);
            }
        }
        idle
    }

    async fn apply_fresh_attestation(
        &self,
        mut request: AttestedConnectRequest,
    ) -> Result<AttestedConnectRequest, EngineError> {
        let refresh = self.attestation_refresh.read().await.clone();
        if let Some(refresh) = refresh {
            let fresh = refresh().map_err(|e| {
                EngineError::Connect(format!("attestation_refresh failed: {e}"))
            })?;
            request.attestation = fresh;
        }
        Ok(request)
    }

    pub async fn gateway_base_url(&self) -> String {
        self.gateway_base_url.read().await.clone()
    }

    pub async fn set_connect_template(&self, request: AttestedConnectRequest) {
        *self.connect_template.write().await = Some(request);
    }

    pub async fn connect_template(&self) -> Option<AttestedConnectRequest> {
        self.connect_template.read().await.clone()
    }

    pub fn handle(self: Arc<Self>) -> SupervisedPoolHandle {
        SupervisedPoolHandle { pool: self }
    }

    pub async fn boot(&self, mut connect_request: AttestedConnectRequest) -> Result<(), EngineError> {
        connect_request.pool_target_size = Some(self.config.pool_target_size);
        *self.connect_template.write().await = Some(connect_request.clone());
        let target = if self.config.supervised {
            self.config.initial_session_count()
        } else {
            self.config.pool_target_size
        };

        let gateway = self.gateway_base_url.read().await.clone();
        info!(
            target,
            gateway = %gateway,
            "supervised pool boot"
        );

        for _ in 0..target {
            self.connect_one(connect_request.clone()).await?;
        }
        Ok(())
    }

    pub async fn connect_one(
        &self,
        request: AttestedConnectRequest,
    ) -> Result<ConnectResult, EngineError> {
        if self.is_circuit_open().await {
            let until = self.state.read().await.circuit_open_until_ms;
            return Err(EngineError::CircuitOpen { until_ms: until });
        }

        let request = self.apply_fresh_attestation(request).await?;
        *self.connect_template.write().await = Some(request.clone());
        let gateway = self.gateway_base_url.read().await.clone();
        match self.connector.connect(request).await {
            Ok(result) => {
                self.state.write().await.consecutive_failures = 0;
                self.state.write().await.slots.push(SessionSlot {
                    session: PoolSession {
                        session_id: result.session_id.clone(),
                        gateway_base_url: gateway,
                    },
                    busy: AtomicBool::new(false),
                });
                if let Err(err) = self.workers.ensure_started(&result.session_id).await {
                    warn_pull_worker_start(&result.session_id, &err);
                }
                self.notify_sessions_changed().await;
                Ok(result)
            }
            Err(err) => {
                self.record_failure().await;
                Err(EngineError::Connect(err.to_string()))
            }
        }
    }

    async fn record_failure(&self) {
        let mut state = self.state.write().await;
        state.consecutive_failures += 1;
        if state.consecutive_failures >= self.config.reconnect.fail_threshold {
            let now_ms = now_ms();
            state.circuit_open_until_ms = now_ms + self.config.reconnect.circuit_ms;
            warn!(
                failures = state.consecutive_failures,
                circuit_ms = self.config.reconnect.circuit_ms,
                "pool reconnect circuit opened"
            );
        }
    }

    async fn is_circuit_open(&self) -> bool {
        let state = self.state.read().await;
        now_ms() < state.circuit_open_until_ms
    }

    pub async fn session_ids(&self) -> Vec<String> {
        self.state
            .read()
            .await
            .slots
            .iter()
            .map(|s| s.session.session_id.clone())
            .collect()
    }

    pub async fn live_session_count(&self) -> u32 {
        self.state.read().await.slots.len() as u32
    }

    pub async fn sessions_by_gateway_url(&self) -> HashMap<String, u32> {
        let mut counts = HashMap::new();
        for slot in &self.state.read().await.slots {
            *counts
                .entry(slot.session.gateway_base_url.clone())
                .or_insert(0) += 1;
        }
        counts
    }

    /// Mark slot busy (tests / fallback when no pull worker is registered).
    pub async fn set_session_busy(&self, session_id: &str, busy: bool) {
        let state = self.state.read().await;
        if let Some(slot) = state
            .slots
            .iter()
            .find(|s| s.session.session_id == session_id)
        {
            slot.busy.store(busy, Ordering::SeqCst);
        }
    }

    pub async fn infer_via_upstream(
        &self,
        model: &str,
        prompt: &str,
    ) -> Result<InferResult, EngineError> {
        self.upstream
            .infer_chat(model, prompt)
            .await
            .map_err(|e| EngineError::Infer(e.to_string()))
    }

    pub async fn scale_to(
        &self,
        target_size: u32,
        connect_request: AttestedConnectRequest,
    ) -> Result<u32, EngineError> {
        let plan = self.scale_pool(target_size).await?;
        if plan.blocked {
            return Err(EngineError::Scale(plan.reason.unwrap_or_default()));
        }
        let mut added = 0u32;
        let current = self.live_session_count().await;
        for _ in current..target_size.min(self.config.pool_target_size.max(target_size)) {
            if self.live_session_count().await >= target_size {
                break;
            }
            self.connect_one(connect_request.clone()).await?;
            added += 1;
        }
        Ok(added)
    }

    /// Plan-only scale math (prefer [`Self::scale_to`] for real capacity changes).
    pub async fn scale_pool(&self, target_size: u32) -> Result<PoolScaleResult, EngineError> {
        let current = self.live_session_count().await;
        let plan = plan_pool_scale(self.config.pool_target_size, current, target_size);
        if plan.blocked {
            return Ok(PoolScaleResult {
                added: 0,
                total: current,
                target_size,
                blocked: true,
                reason: plan.reason,
            });
        }
        Ok(PoolScaleResult {
            added: plan.to_add,
            total: current + plan.to_add,
            target_size: plan.target_size,
            blocked: false,
            reason: None,
        })
    }

    pub async fn drain_idle_pool(&self, fraction: f64) -> Result<PoolDrainResult, EngineError> {
        self.drain_with_plan(None, Some(fraction)).await
    }

    pub async fn drain_idle_sessions(&self, count: u32) -> Result<PoolDrainResult, EngineError> {
        self.drain_with_plan(Some(count), None).await
    }

    async fn drain_with_plan(
        &self,
        count: Option<u32>,
        fraction: Option<f64>,
    ) -> Result<PoolDrainResult, EngineError> {
        let current = self.live_session_count().await;
        let idle_ids = self.idle_session_ids().await;
        let idle = idle_ids.len() as u32;
        let plan = plan_pool_drain(
            self.config.pool_target_size,
            current,
            fraction,
            count,
            idle,
        );

        let mut drained = 0u32;
        for session_id in idle_ids.into_iter().take(plan.to_drain as usize) {
            // TS drainSlotAt: stop pull worker, then disconnect, then remove slot.
            if self.session_is_busy(&session_id).await {
                continue;
            }
            self.workers.stop_session(&session_id).await;
            if let Err(err) = self.connector.disconnect(&session_id).await {
                warn!(session_id = %session_id, error = %err, "disconnect failed during drain");
            }
            let mut state = self.state.write().await;
            if let Some(index) = state
                .slots
                .iter()
                .position(|s| s.session.session_id == session_id)
            {
                state.slots.remove(index);
                drained += 1;
            }
        }

        self.notify_sessions_changed().await;
        let remaining = self.live_session_count().await;
        Ok(PoolDrainResult {
            drained,
            remaining,
            target_remaining: plan.target_remaining,
            blocked: plan.blocked || (plan.to_drain > 0 && drained < plan.to_drain),
            reason: plan.reason,
        })
    }

    /// Make-before-break gateway migration: dial target first, then disconnect source.
    pub async fn migrate_gateway_pool(
        &self,
        target_url: &str,
        fraction: f64,
    ) -> Result<GatewayMigrationResult, EngineError> {
        let normalized = target_url.trim().to_string();
        if normalized.is_empty() {
            return Err(EngineError::Connect("empty migration target_url".into()));
        }

        let template = self.connect_template.read().await.clone().ok_or_else(|| {
            EngineError::Connect("no connect template; boot the pool first".into())
        })?;

        let state = self.state.read().await;
        let pool_size = state.slots.len() as u32;
        let on_target = state
            .slots
            .iter()
            .filter(|s| s.session.gateway_base_url == normalized)
            .count() as u32;
        drop(state);

        let source_ids: Vec<(usize, String)> = {
            let state = self.state.read().await;
            state
                .slots
                .iter()
                .enumerate()
                .filter(|(_, s)| s.session.gateway_base_url != normalized)
                .map(|(i, s)| (i, s.session.session_id.clone()))
                .collect()
        };
        let mut idle_on_source = 0u32;
        for (_, id) in &source_ids {
            if !self.session_is_busy(id).await {
                idle_on_source += 1;
            }
        }
        let plan = plan_gateway_migration(pool_size, on_target, fraction, idle_on_source);

        let mut moved = 0u32;
        for _ in 0..plan.to_move {
            let candidates: Vec<(usize, String)> = {
                let state = self.state.read().await;
                state
                    .slots
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| s.session.gateway_base_url != normalized)
                    .map(|(i, s)| (i, s.session.session_id.clone()))
                    .collect()
            };
            let mut found = None;
            for (i, sid) in candidates {
                if !self.session_is_busy(&sid).await {
                    found = Some((i, sid));
                    break;
                }
            }
            let Some((index, old_session_id)) = found else {
                break;
            };

            let mut req = template.clone();
            req.session_id = uuid::Uuid::new_v4().to_string();
            req.gateway_challenge_nonce =
                Some(crate::plane::generate_gateway_connect_challenge_nonce());
            let req = self.apply_fresh_attestation(req).await?;
            *self.connect_template.write().await = Some(req.clone());

            let new_conn = match self.connector.connect_to(&normalized, req).await {
                Ok(r) => r,
                Err(err) => {
                    warn!(error = %err, target = %normalized, "migrate connect_to failed");
                    return Err(EngineError::Connect(err.to_string()));
                }
            };
            let new_session_id = new_conn.session_id.clone();

            // Stop source puller before disconnect (TS migrateOneSession).
            self.workers.stop_session(&old_session_id).await;
            if let Err(err) = self.connector.disconnect(&old_session_id).await {
                warn!(
                    session_id = %old_session_id,
                    error = %err,
                    "migrate source disconnect failed; keeping both sessions mapped carefully"
                );
            }

            let mut state = self.state.write().await;
            if let Some(slot) = state.slots.get_mut(index) {
                if slot.session.session_id == old_session_id {
                    slot.session.session_id = new_session_id.clone();
                    slot.session.gateway_base_url = normalized.clone();
                    slot.busy.store(false, Ordering::SeqCst);
                    moved += 1;
                } else {
                    state.slots.push(SessionSlot {
                        session: PoolSession {
                            session_id: new_session_id.clone(),
                            gateway_base_url: normalized.clone(),
                        },
                        busy: AtomicBool::new(false),
                    });
                    moved += 1;
                }
            }
            drop(state);

            if let Err(err) = self.workers.ensure_started(&new_session_id).await {
                warn_pull_worker_start(&new_session_id, &err);
            }
        }

        if moved > 0 {
            *self.gateway_base_url.write().await = normalized.clone();
            self.notify_sessions_changed().await;
        }

        let state = self.state.read().await;
        let final_on_target = state
            .slots
            .iter()
            .filter(|s| s.session.gateway_base_url == normalized)
            .count() as u32;
        let on_source = state.slots.len() as u32 - final_on_target;

        Ok(GatewayMigrationResult {
            moved,
            on_target: final_on_target,
            on_source,
            target_count: plan.target_count,
            blocked: plan.blocked && moved < plan.to_move,
            reason: plan.reason,
        })
    }

    pub async fn close_all(&self) -> Result<(), EngineError> {
        let ids: Vec<String> = self.session_ids().await;
        for id in ids {
            self.workers.stop_session(&id).await;
            if let Err(err) = self.connector.disconnect(&id).await {
                warn!(session_id = %id, error = %err, "disconnect failed during pool close");
            }
        }
        self.workers.stop_all().await;
        self.state.write().await.slots.clear();
        self.notify_sessions_changed().await;
        Ok(())
    }
}

impl SupervisedPoolHandle {
    pub fn inner(&self) -> &Arc<SupervisedPool> {
        &self.pool
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn sessions_by_gateway_url_from_slots(
    slots: &[PoolSession],
) -> HashMap<String, u32> {
    let mut counts = HashMap::new();
    for slot in slots {
        let url = slot.gateway_base_url.trim();
        if url.is_empty() {
            continue;
        }
        *counts.entry(url.to_string()).or_insert(0) += 1;
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PoolReconnectConfig, SupervisedPoolConfig};
    use async_trait::async_trait;
    use ie_protocol::{
        AttestationBundle, AttestationVerdict, AttestedConnectRequest, AttestedConnectResponse,
        CpuTeeAttestation, CpuTeeKind, EngineStartupIdentity, GpuTeeAttestation, GpuTeeKind,
        WorkloadMeasurements,
    };

    use std::sync::atomic::{AtomicU32, Ordering};

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
                format!("{}-{}", request.session_id, NEXT_ID.fetch_add(1, Ordering::SeqCst))
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

        async fn disconnect(&self, _session_id: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
            session_id: "sess-1".into(),
            engine_id: "engine-1".into(),
            models: vec!["gemma".into()],
            identity: EngineStartupIdentity {
                engine_id: "engine-1".into(),
                kex: "kex".into(),
                ed25519_public: "pk".into(),
            },
            attestation: AttestationBundle {
                cpu_tee: CpuTeeAttestation {
                    kind: CpuTeeKind::SevSnp,
                    quote: "q".into(),
                    verdict: AttestationVerdict::Pass,
                    policy_id: "p".into(),
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
            pool_target_size: None,
            instance_id: None,
            gateway_challenge_nonce: None,
        }
    }

    fn pool_cfg() -> SupervisedPoolConfig {
        SupervisedPoolConfig {
            pool_target_size: 4,
            pool_initial_fraction: 0.5,
            pool_initial_fraction_explicit: true,
            pool_baseline: 4,
            supervised: true,
            reconnect: PoolReconnectConfig::default(),
        }
    }

    #[tokio::test]
    async fn boots_initial_fraction() {
        let pool = Arc::new(SupervisedPool::new(
            pool_cfg(),
            "https://gateway.example",
            Arc::new(MockConnector),
            Arc::new(MockUpstream),
        ));
        pool.boot(sample_request()).await.unwrap();
        assert_eq!(pool.session_ids().await.len(), 2);
    }

    #[tokio::test]
    async fn drain_idle_pool_half() {
        let pool = Arc::new(SupervisedPool::new(
            SupervisedPoolConfig {
                pool_target_size: 2,
                pool_initial_fraction: 1.0,
                pool_initial_fraction_explicit: true,
                pool_baseline: 4,
                supervised: true,
                reconnect: PoolReconnectConfig::default(),
            },
            "https://gateway.example",
            Arc::new(MockConnector),
            Arc::new(MockUpstream),
        ));
        pool.boot(sample_request()).await.unwrap();
        let result = pool.drain_idle_pool(0.5).await.unwrap();
        assert_eq!(result.drained, 1);
        assert_eq!(result.remaining, 1);
    }

    #[tokio::test]
    async fn drain_skips_busy_sessions() {
        let pool = Arc::new(SupervisedPool::new(
            SupervisedPoolConfig {
                pool_target_size: 2,
                pool_initial_fraction: 1.0,
                pool_initial_fraction_explicit: true,
                pool_baseline: 4,
                supervised: true,
                reconnect: PoolReconnectConfig::default(),
            },
            "https://gateway.example",
            Arc::new(MockConnector),
            Arc::new(MockUpstream),
        ));
        pool.boot(sample_request()).await.unwrap();
        let ids = pool.session_ids().await;
        assert_eq!(ids.len(), 2);
        pool.set_session_busy(&ids[0], true).await;
        let result = pool.drain_idle_sessions(2).await.unwrap();
        assert_eq!(result.drained, 1);
        assert_eq!(result.remaining, 1);
        assert!(pool.session_ids().await.contains(&ids[0]));
    }

    #[tokio::test]
    async fn migrate_gateway_pool_moves_idle_sessions() {
        let pool = Arc::new(SupervisedPool::new(
            SupervisedPoolConfig {
                pool_target_size: 4,
                pool_initial_fraction: 1.0,
                pool_initial_fraction_explicit: true,
                pool_baseline: 4,
                supervised: true,
                reconnect: PoolReconnectConfig::default(),
            },
            "https://gateway-old",
            Arc::new(MockConnector),
            Arc::new(MockUpstream),
        ));
        pool.boot({
            let mut r1 = sample_request();
            r1.session_id = "boot-1".into();
            r1
        }).await.unwrap();
        let mut r2 = sample_request();
        r2.session_id = "boot-2".into();
        pool.connect_one(r2).await.unwrap();
        let result = pool
            .migrate_gateway_pool("https://gateway-new", 0.5)
            .await
            .unwrap();
        assert!(result.moved >= 1);
        let counts = pool.sessions_by_gateway_url().await;
        assert!(counts.get("https://gateway-new").copied().unwrap_or(0) >= 1);
    }
}
