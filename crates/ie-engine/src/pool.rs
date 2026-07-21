use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;
use tracing::{info, warn};

use ie_protocol::{AttestationBundle, AttestedConnectRequest};

use crate::config::SupervisedPoolConfig;
use crate::cutover::{
    map_with_concurrency, plan_pool_drain, plan_pool_scale, PoolConnectThrottle,
    DEFAULT_POOL_CONNECT_CONCURRENCY, DEFAULT_POOL_CONNECT_STAGGER_MS,
};
use crate::error::EngineError;
use crate::gateway_migration::plan_gateway_migration;
use crate::pull_workers::{
    warn_pull_worker_start, PullWorkerRegistry, PullWorkerStartFn, SessionReadyFn,
    SessionsChangedFn,
};
use crate::traits::{ConnectResult, EnginePlaneConnector, InferenceUpstream, InferResult};

/// Remint attestation before reconnect / scale / migrate (optional).
pub type AttestationRefreshFn =
    Arc<dyn Fn() -> Result<AttestationBundle, String> + Send + Sync>;

const SESSION_WATCH_INTERVAL_MS: u64 = 5_000;

#[derive(Debug, Clone)]
pub struct PoolSession {
    pub session_id: String,
    pub gateway_base_url: String,
}

struct SessionSlot {
    session: PoolSession,
    busy: AtomicBool,
    reconnect_attempt: AtomicU32,
    reconnect_pending: AtomicBool,
    /// Set while draining / closing so close watch does not re-dial.
    suppress_reconnect: AtomicBool,
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
    /// Sliding window of reconnect failure timestamps (TS poolReconnectFailureTimes).
    reconnect_failure_times_ms: VecDeque<u64>,
}

impl Default for SessionSlot {
    fn default() -> Self {
        Self {
            session: PoolSession {
                session_id: String::new(),
                gateway_base_url: String::new(),
            },
            busy: AtomicBool::new(false),
            reconnect_attempt: AtomicU32::new(0),
            reconnect_pending: AtomicBool::new(false),
            suppress_reconnect: AtomicBool::new(false),
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
    /// Post current epoch after connect / reconnect.
    on_session_ready: RwLock<Option<SessionReadyFn>>,
    closed: AtomicBool,
    /// Suppress per-session epoch register during [`Self::boot`] (bulk register follows).
    booting: AtomicBool,
    /// Shared across boot / scale / migrate / reconnect (TS `connectThrottle`).
    connect_throttle: Arc<PoolConnectThrottle>,
    state: RwLock<PoolState>,
    watch_task: RwLock<Option<tokio::task::JoinHandle<()>>>,
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
            on_session_ready: RwLock::new(None),
            closed: AtomicBool::new(false),
            booting: AtomicBool::new(false),
            connect_throttle: Arc::new(PoolConnectThrottle::new(
                DEFAULT_POOL_CONNECT_CONCURRENCY,
                DEFAULT_POOL_CONNECT_STAGGER_MS,
            )),
            state: RwLock::new(PoolState::default()),
            watch_task: RwLock::new(None),
        }
    }

    /// Replace connect throttle (call before boot; used by ie-bin from env).
    pub fn with_connect_throttle(mut self, throttle: PoolConnectThrottle) -> Self {
        self.connect_throttle = Arc::new(throttle);
        self
    }

    pub fn connect_throttle(&self) -> &PoolConnectThrottle {
        self.connect_throttle.as_ref()
    }

    /// Install / replace attestation remint used on scale + migrate (+ reconnect paths).
    pub async fn set_attestation_refresh(&self, refresh: Option<AttestationRefreshFn>) {
        *self.attestation_refresh.write().await = refresh;
    }

    async fn throttled_connect(
        &self,
        request: AttestedConnectRequest,
    ) -> Result<ConnectResult, Box<dyn std::error::Error + Send + Sync>> {
        let connector = Arc::clone(&self.connector);
        self.connect_throttle
            .run(move || async move { connector.connect(request).await })
            .await
    }

    async fn throttled_connect_to(
        &self,
        gateway_base_url: &str,
        request: AttestedConnectRequest,
    ) -> Result<ConnectResult, Box<dyn std::error::Error + Send + Sync>> {
        let connector = Arc::clone(&self.connector);
        let url = gateway_base_url.to_string();
        self.connect_throttle
            .run(move || async move { connector.connect_to(&url, request).await })
            .await
    }

    async fn throttled_reconnect(
        &self,
        session_id: &str,
        gateway_base_url: &str,
        request: AttestedConnectRequest,
    ) -> Result<ConnectResult, Box<dyn std::error::Error + Send + Sync>> {
        let connector = Arc::clone(&self.connector);
        let session_id = session_id.to_string();
        let url = gateway_base_url.to_string();
        self.connect_throttle
            .run(move || async move { connector.reconnect(&session_id, &url, request).await })
            .await
    }

    /// Register pull-worker factory (required for live H2; unit tests leave unset).
    pub async fn set_pull_worker_start_fn(&self, start_fn: Option<PullWorkerStartFn>) {
        self.workers.set_start_fn(start_fn).await;
    }

    pub async fn set_on_sessions_changed(&self, cb: Option<SessionsChangedFn>) {
        *self.on_sessions_changed.write().await = cb;
    }

    pub async fn set_on_session_ready(&self, cb: Option<SessionReadyFn>) {
        *self.on_session_ready.write().await = cb;
    }

    pub fn workers(&self) -> &PullWorkerRegistry {
        &self.workers
    }

    /// Start the 5s closed-transport watch (TS `sessionWatchTimer`).
    pub async fn start_session_watch(self: &Arc<Self>) {
        if self.watch_task.read().await.is_some() {
            return;
        }
        let pool = Arc::clone(self);
        let handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(SESSION_WATCH_INTERVAL_MS)).await;
                if pool.closed.load(Ordering::SeqCst) {
                    break;
                }
                let ids = pool.session_ids().await;
                for sid in ids {
                    if pool.connector.is_session_closed(&sid).await {
                        pool.schedule_reconnect(sid);
                    }
                }
            }
        });
        *self.watch_task.write().await = Some(handle);
    }

    /// Pull-worker / transport path entry (TS `bindSessionClose` → `scheduleReconnect`).
    pub fn notify_transport_lost(self: &Arc<Self>, session_id: impl Into<String>) {
        self.schedule_reconnect(session_id.into());
    }

    fn reconnect_delay_ms(&self, attempt: u32) -> u64 {
        let base = self.config.reconnect.reconnect_base_ms.max(1);
        let max = self.config.reconnect.reconnect_max_ms.max(base);
        let shift = attempt.min(5);
        base.saturating_mul(1u64 << shift).min(max)
    }

    async fn circuit_delay_ms(&self) -> u64 {
        let until = self.state.read().await.circuit_open_until_ms;
        until.saturating_sub(now_ms())
    }

    async fn record_reconnect_failure(&self) {
        let now = now_ms();
        let window = self.config.reconnect.fail_window_ms;
        let threshold = self.config.reconnect.fail_threshold;
        let circuit_ms = self.config.reconnect.circuit_ms;
        let mut state = self.state.write().await;
        while state
            .reconnect_failure_times_ms
            .front()
            .is_some_and(|t| now.saturating_sub(*t) > window)
        {
            state.reconnect_failure_times_ms.pop_front();
        }
        state.reconnect_failure_times_ms.push_back(now);
        if state.reconnect_failure_times_ms.len() as u32 >= threshold {
            state.circuit_open_until_ms = now + circuit_ms;
            state.reconnect_failure_times_ms.clear();
            warn!(
                circuit_ms,
                "pool reconnect circuit opened (failure window)"
            );
        }
    }

    async fn clear_reconnect_circuit(&self) {
        let mut state = self.state.write().await;
        state.reconnect_failure_times_ms.clear();
        state.circuit_open_until_ms = 0;
        state.consecutive_failures = 0;
    }

    fn schedule_reconnect(self: &Arc<Self>, session_id: String) {
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        let pool = Arc::clone(self);
        tokio::spawn(async move {
            let attempt = {
                let state = pool.state.read().await;
                let Some(slot) = state
                    .slots
                    .iter()
                    .find(|s| s.session.session_id == session_id)
                else {
                    return;
                };
                if slot.suppress_reconnect.load(Ordering::SeqCst) {
                    return;
                }
                if slot
                    .reconnect_pending
                    .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                    .is_err()
                {
                    return;
                }
                slot.reconnect_attempt.load(Ordering::SeqCst)
            };
            let delay = pool
                .reconnect_delay_ms(attempt)
                .max(pool.circuit_delay_ms().await);
            tokio::time::sleep(Duration::from_millis(delay)).await;
            pool.reconnect_slot(&session_id).await;
        });
    }

    async fn reconnect_slot(self: &Arc<Self>, session_id: &str) {
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        let (gateway_url, attempt) = {
            let state = self.state.read().await;
            let Some(slot) = state
                .slots
                .iter()
                .find(|s| s.session.session_id == session_id)
            else {
                return;
            };
            if slot.suppress_reconnect.load(Ordering::SeqCst) {
                slot.reconnect_pending.store(false, Ordering::SeqCst);
                return;
            }
            let attempt = slot.reconnect_attempt.fetch_add(1, Ordering::SeqCst) + 1;
            (slot.session.gateway_base_url.clone(), attempt)
        };

        self.workers.stop_session(session_id).await;
        let _ = self.connector.teardown_for_reconnect(session_id).await;

        let template = match self.connect_template().await {
            Some(t) => t,
            None => {
                warn!(session_id, "reconnect aborted: no connect template");
                self.record_reconnect_failure().await;
                self.clear_reconnect_pending(session_id).await;
                self.schedule_reconnect(session_id.to_string());
                return;
            }
        };

        let mut request = match self.apply_fresh_attestation(template).await {
            Ok(r) => r,
            Err(err) => {
                warn!(session_id, error = %err, "reconnect attestation refresh failed");
                self.record_reconnect_failure().await;
                self.clear_reconnect_pending(session_id).await;
                self.schedule_reconnect(session_id.to_string());
                return;
            }
        };
        request.session_id = session_id.to_string();

        match self
            .throttled_reconnect(session_id, &gateway_url, request)
            .await
        {
            Ok(result) => {
                if result.session_id != session_id {
                    warn!(
                        expected = session_id,
                        got = %result.session_id,
                        "reconnect returned different session id"
                    );
                }
                {
                    let state = self.state.read().await;
                    if let Some(slot) = state
                        .slots
                        .iter()
                        .find(|s| s.session.session_id == session_id)
                    {
                        slot.reconnect_attempt.store(0, Ordering::SeqCst);
                        slot.busy.store(false, Ordering::SeqCst);
                    }
                }
                if let Err(err) = self.invoke_session_ready(session_id).await {
                    warn!(session_id, error = %err, "reconnect epoch register failed");
                }
                if let Err(err) = self.workers.ensure_started(session_id).await {
                    warn_pull_worker_start(session_id, &err);
                }
                self.clear_reconnect_circuit().await;
                self.clear_reconnect_pending(session_id).await;
                info!(session_id, attempt, "engine session reconnected");
            }
            Err(err) => {
                warn!(session_id, attempt, error = %err, "engine session reconnect failed");
                self.record_reconnect_failure().await;
                self.clear_reconnect_pending(session_id).await;
                self.schedule_reconnect(session_id.to_string());
            }
        }
    }

    async fn clear_reconnect_pending(&self, session_id: &str) {
        let state = self.state.read().await;
        if let Some(slot) = state
            .slots
            .iter()
            .find(|s| s.session.session_id == session_id)
        {
            slot.reconnect_pending.store(false, Ordering::SeqCst);
        }
    }

    async fn invoke_session_ready(&self, session_id: &str) -> Result<(), String> {
        let ready = self.on_session_ready.read().await.clone();
        if let Some(ready) = ready {
            ready(session_id.to_string()).await?;
        }
        Ok(())
    }

    async fn suppress_reconnect(&self, session_id: &str) {
        let state = self.state.read().await;
        if let Some(slot) = state
            .slots
            .iter()
            .find(|s| s.session.session_id == session_id)
        {
            slot.suppress_reconnect.store(true, Ordering::SeqCst);
            slot.reconnect_pending.store(false, Ordering::SeqCst);
        }
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

    pub async fn boot(
        self: &Arc<Self>,
        mut connect_request: AttestedConnectRequest,
    ) -> Result<(), EngineError> {
        connect_request.pool_target_size = Some(self.config.pool_target_size);
        *self.connect_template.write().await = Some(connect_request.clone());
        let target = if self.config.supervised {
            self.config.initial_session_count()
        } else {
            self.config.pool_target_size
        };

        let gateway = self.gateway_base_url.read().await.clone();
        let concurrency = self.connect_throttle.concurrency().min(target.max(1));
        info!(
            target,
            concurrency,
            stagger_ms = self.connect_throttle.stagger_ms(),
            gateway = %gateway,
            "supervised pool boot"
        );

        self.booting.store(true, Ordering::SeqCst);
        let pool = Arc::clone(self);
        let req = connect_request;
        let results = map_with_concurrency(target, concurrency, move |_| {
            let pool = Arc::clone(&pool);
            let req = req.clone();
            async move { pool.connect_one(req).await }
        })
        .await;
        self.booting.store(false, Ordering::SeqCst);
        for result in results {
            result?;
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
        match self.throttled_connect(request).await {
            Ok(result) => {
                self.state.write().await.consecutive_failures = 0;
                self.state.write().await.slots.push(SessionSlot {
                    session: PoolSession {
                        session_id: result.session_id.clone(),
                        gateway_base_url: gateway,
                    },
                    ..SessionSlot::default()
                });
                // Boot uses bulk `register_initial_epoch`; scale/reconnect register per session.
                // Pull workers also wait until after boot's bulk epoch register (TS parity:
                // `attachSlotCore` connects only; boot registers epoch, then starts pull workers)
                // so the long-poll never contends with the ephemeral epoch POST.
                if !self.booting.load(Ordering::SeqCst) {
                    if let Err(err) = self.invoke_session_ready(&result.session_id).await {
                        warn!(
                            session_id = %result.session_id,
                            error = %err,
                            "session ready (epoch) failed"
                        );
                    }
                    if let Err(err) = self.workers.ensure_started(&result.session_id).await {
                        warn_pull_worker_start(&result.session_id, &err);
                    }
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
        self: &Arc<Self>,
        target_size: u32,
        connect_request: AttestedConnectRequest,
    ) -> Result<u32, EngineError> {
        let plan = self.scale_pool(target_size).await?;
        if plan.blocked {
            return Err(EngineError::Scale(plan.reason.unwrap_or_default()));
        }
        let to_add = plan.added;
        if to_add == 0 {
            return Ok(0);
        }
        let concurrency = self.connect_throttle.concurrency().min(to_add);
        let pool = Arc::clone(self);
        let results = map_with_concurrency(to_add, concurrency, move |_| {
            let pool = Arc::clone(&pool);
            let req = connect_request.clone();
            async move { pool.connect_one(req).await }
        })
        .await;
        let mut added = 0u32;
        for result in results {
            result?;
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
            self.suppress_reconnect(&session_id).await;
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

        // Sticky primary: reconnect/scale must dial the migration target (TS sets at start).
        *self.gateway_base_url.write().await = normalized.clone();
        self.connector
            .set_primary_gateway_url(&normalized)
            .await;

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

            let new_conn = match self.throttled_connect_to(&normalized, req).await {
                Ok(r) => r,
                Err(err) => {
                    warn!(error = %err, target = %normalized, "migrate connect_to failed");
                    return Err(EngineError::Connect(err.to_string()));
                }
            };
            let new_session_id = new_conn.session_id.clone();

            // Stop source puller before disconnect (TS migrateOneSession).
            self.suppress_reconnect(&old_session_id).await;
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
                    slot.suppress_reconnect.store(false, Ordering::SeqCst);
                    slot.reconnect_pending.store(false, Ordering::SeqCst);
                    slot.reconnect_attempt.store(0, Ordering::SeqCst);
                    moved += 1;
                } else {
                    state.slots.push(SessionSlot {
                        session: PoolSession {
                            session_id: new_session_id.clone(),
                            gateway_base_url: normalized.clone(),
                        },
                        ..SessionSlot::default()
                    });
                    moved += 1;
                }
            }
            drop(state);

            if let Err(err) = self.invoke_session_ready(&new_session_id).await {
                warn!(
                    session_id = %new_session_id,
                    error = %err,
                    "migrate session ready (epoch) failed"
                );
            }
            if let Err(err) = self.workers.ensure_started(&new_session_id).await {
                warn_pull_worker_start(&new_session_id, &err);
            }
        }

        if moved > 0 {
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
        self.closed.store(true, Ordering::SeqCst);
        if let Some(handle) = self.watch_task.write().await.take() {
            handle.abort();
        }
        let ids: Vec<String> = self.session_ids().await;
        for id in ids {
            self.suppress_reconnect(&id).await;
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

    fn test_pool(
        config: SupervisedPoolConfig,
        gateway: &str,
        connector: Arc<dyn EnginePlaneConnector>,
    ) -> Arc<SupervisedPool> {
        Arc::new(
            SupervisedPool::new(config, gateway, connector, Arc::new(MockUpstream))
                // Fast tests: no stagger between dials.
                .with_connect_throttle(PoolConnectThrottle::new(8, 0)),
        )
    }

    #[tokio::test]
    async fn boots_initial_fraction() {
        let pool = test_pool(
            pool_cfg(),
            "https://gateway.example",
            Arc::new(MockConnector),
        );
        pool.boot(sample_request()).await.unwrap();
        assert_eq!(pool.session_ids().await.len(), 2);
    }

    #[tokio::test]
    async fn drain_idle_pool_half() {
        let pool = test_pool(
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
        );
        pool.boot(sample_request()).await.unwrap();
        let result = pool.drain_idle_pool(0.5).await.unwrap();
        assert_eq!(result.drained, 1);
        assert_eq!(result.remaining, 1);
    }

    #[tokio::test]
    async fn drain_skips_busy_sessions() {
        let pool = test_pool(
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
        );
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
        let pool = test_pool(
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
        );
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
        assert_eq!(pool.gateway_base_url().await, "https://gateway-new");
        let counts = pool.sessions_by_gateway_url().await;
        assert!(counts.get("https://gateway-new").copied().unwrap_or(0) >= 1);
    }

    struct StickyMock {
        primary: tokio::sync::Mutex<String>,
        inner: MockConnector,
    }

    impl StickyMock {
        fn new(primary: &str) -> Self {
            Self {
                primary: tokio::sync::Mutex::new(primary.to_string()),
                inner: MockConnector,
            }
        }
    }

    #[async_trait]
    impl EnginePlaneConnector for StickyMock {
        async fn connect(
            &self,
            request: AttestedConnectRequest,
        ) -> Result<ConnectResult, Box<dyn std::error::Error + Send + Sync>> {
            self.inner.connect(request).await
        }

        async fn disconnect(
            &self,
            session_id: &str,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.inner.disconnect(session_id).await
        }

        async fn set_primary_gateway_url(&self, gateway_base_url: &str) {
            *self.primary.lock().await = gateway_base_url.to_string();
        }
    }

    #[tokio::test]
    async fn migrate_sets_sticky_primary_even_when_zero_moves() {
        let connector = Arc::new(StickyMock::new("https://gateway-old"));
        let pool = test_pool(
            SupervisedPoolConfig {
                pool_target_size: 1,
                pool_initial_fraction: 1.0,
                pool_initial_fraction_explicit: true,
                pool_baseline: 1,
                supervised: true,
                reconnect: PoolReconnectConfig::default(),
            },
            "https://gateway-old",
            connector.clone() as Arc<dyn EnginePlaneConnector>,
        );
        let mut req = sample_request();
        req.session_id = "busy-1".into();
        pool.boot(req).await.unwrap();
        let ids = pool.session_ids().await;
        pool.set_session_busy(&ids[0], true).await;
        let result = pool
            .migrate_gateway_pool("https://gateway-new", 1.0)
            .await
            .unwrap();
        assert_eq!(result.moved, 0);
        assert_eq!(pool.gateway_base_url().await, "https://gateway-new");
        assert_eq!(
            connector.primary.lock().await.as_str(),
            "https://gateway-new"
        );
    }

    struct ReconnectMock {
        live: tokio::sync::Mutex<HashMap<String, bool>>,
        reconnects: AtomicU32,
        teardowns: AtomicU32,
    }

    impl ReconnectMock {
        fn new() -> Self {
            Self {
                live: tokio::sync::Mutex::new(HashMap::new()),
                reconnects: AtomicU32::new(0),
                teardowns: AtomicU32::new(0),
            }
        }
    }

    #[async_trait]
    impl EnginePlaneConnector for ReconnectMock {
        async fn connect(
            &self,
            request: AttestedConnectRequest,
        ) -> Result<ConnectResult, Box<dyn std::error::Error + Send + Sync>> {
            let sid = if request.session_id.is_empty() {
                format!("sess-{}", NEXT_ID.fetch_add(1, Ordering::SeqCst))
            } else {
                request.session_id
            };
            self.live.lock().await.insert(sid.clone(), true);
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
            session_id: &str,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.live.lock().await.remove(session_id);
            Ok(())
        }

        async fn is_session_closed(&self, session_id: &str) -> bool {
            !self.live.lock().await.get(session_id).copied().unwrap_or(false)
        }

        async fn teardown_for_reconnect(
            &self,
            session_id: &str,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.teardowns.fetch_add(1, Ordering::SeqCst);
            self.live.lock().await.insert(session_id.to_string(), false);
            Ok(())
        }

        async fn reconnect(
            &self,
            session_id: &str,
            _gateway_base_url: &str,
            _request: AttestedConnectRequest,
        ) -> Result<ConnectResult, Box<dyn std::error::Error + Send + Sync>> {
            self.reconnects.fetch_add(1, Ordering::SeqCst);
            self.live.lock().await.insert(session_id.to_string(), true);
            Ok(ConnectResult {
                session_id: session_id.to_string(),
                response: AttestedConnectResponse {
                    ok: true,
                    gateway_attestation: None,
                    pool_target_ack: Some(1),
                    gateway_challenge_nonce: None,
                },
            })
        }
    }

    #[tokio::test]
    async fn reconnect_keeps_session_id() {
        let connector = Arc::new(ReconnectMock::new());
        let pool = test_pool(
            SupervisedPoolConfig {
                pool_target_size: 1,
                pool_initial_fraction: 1.0,
                pool_initial_fraction_explicit: true,
                pool_baseline: 1,
                supervised: true,
                reconnect: PoolReconnectConfig {
                    fail_threshold: 8,
                    fail_window_ms: 10_000,
                    circuit_ms: 30_000,
                    reconnect_base_ms: 10,
                    reconnect_max_ms: 50,
                },
            },
            "https://gateway.example",
            connector.clone() as Arc<dyn EnginePlaneConnector>,
        );
        let mut req = sample_request();
        req.session_id = "sticky-1".into();
        pool.boot(req).await.unwrap();
        let ids = pool.session_ids().await;
        assert_eq!(ids, vec!["sticky-1".to_string()]);

        // Simulate transport death.
        connector.live.lock().await.insert("sticky-1".into(), false);
        pool.notify_transport_lost("sticky-1");

        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while connector.reconnects.load(Ordering::SeqCst) == 0 {
            if tokio::time::Instant::now() > deadline {
                panic!("timed out waiting for reconnect");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        assert_eq!(pool.session_ids().await, vec!["sticky-1".to_string()]);
        assert!(connector.teardowns.load(Ordering::SeqCst) >= 1);
        assert!(connector
            .live
            .lock()
            .await
            .get("sticky-1")
            .copied()
            .unwrap_or(false));
        pool.close_all().await.unwrap();
    }

    #[tokio::test]
    async fn drain_suppresses_reconnect() {
        let connector = Arc::new(ReconnectMock::new());
        let pool = test_pool(
            SupervisedPoolConfig {
                pool_target_size: 1,
                pool_initial_fraction: 1.0,
                pool_initial_fraction_explicit: true,
                pool_baseline: 1,
                supervised: true,
                reconnect: PoolReconnectConfig {
                    reconnect_base_ms: 10,
                    reconnect_max_ms: 20,
                    ..PoolReconnectConfig::default()
                },
            },
            "https://gateway.example",
            connector.clone() as Arc<dyn EnginePlaneConnector>,
        );
        let mut req = sample_request();
        req.session_id = "drain-1".into();
        pool.boot(req).await.unwrap();
        pool.drain_idle_sessions(1).await.unwrap();
        pool.notify_transport_lost("drain-1");
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(connector.reconnects.load(Ordering::SeqCst), 0);
        assert!(pool.session_ids().await.is_empty());
    }
}
