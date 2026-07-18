use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;
use tracing::{info, warn};

use ie_protocol::AttestedConnectRequest;

use crate::config::SupervisedPoolConfig;
use crate::error::EngineError;
use crate::traits::{ConnectResult, EnginePlaneConnector, InferenceUpstream, InferResult};

#[derive(Debug, Clone)]
pub struct PoolSession {
    pub session_id: String,
    pub gateway_base_url: String,
}

#[derive(Debug, Default)]
struct PoolState {
    sessions: Vec<PoolSession>,
    consecutive_failures: u32,
    circuit_open_until_ms: u64,
}

pub struct SupervisedPool {
    config: SupervisedPoolConfig,
    gateway_base_url: String,
    connector: Arc<dyn EnginePlaneConnector>,
    upstream: Arc<dyn InferenceUpstream>,
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
            gateway_base_url: gateway_base_url.into(),
            connector,
            upstream,
            state: RwLock::new(PoolState::default()),
        }
    }

    pub fn handle(self: Arc<Self>) -> SupervisedPoolHandle {
        SupervisedPoolHandle { pool: self }
    }

    pub async fn boot(&self, mut connect_request: AttestedConnectRequest) -> Result<(), EngineError> {
        connect_request.pool_target_size = Some(self.config.pool_target_size);
        let target = if self.config.supervised {
            self.config.initial_session_count()
        } else {
            self.config.pool_target_size
        };

        info!(
            target,
            gateway = %self.gateway_base_url,
            "supervised pool boot"
        );

        for _ in 0..target {
            self.connect_one(connect_request.clone()).await?;
        }
        Ok(())
    }

    async fn connect_one(&self, request: AttestedConnectRequest) -> Result<ConnectResult, EngineError> {
        if self.is_circuit_open().await {
            let until = self.state.read().await.circuit_open_until_ms;
            return Err(EngineError::CircuitOpen { until_ms: until });
        }

        match self.connector.connect(request).await {
            Ok(result) => {
                self.state.write().await.consecutive_failures = 0;
                self.state.write().await.sessions.push(PoolSession {
                    session_id: result.session_id.clone(),
                    gateway_base_url: self.gateway_base_url.clone(),
                });
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
            .sessions
            .iter()
            .map(|s| s.session_id.clone())
            .collect()
    }

    pub async fn sessions_by_gateway_url(&self) -> std::collections::HashMap<String, u32> {
        let mut counts = std::collections::HashMap::new();
        for session in &self.state.read().await.sessions {
            *counts.entry(session.gateway_base_url.clone()).or_insert(0) += 1;
        }
        counts
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

    pub async fn scale_to(&self, target_size: u32, connect_request: AttestedConnectRequest) -> Result<u32, EngineError> {
        let current = self.state.read().await.sessions.len() as u32;
        if current >= target_size {
            return Ok(0);
        }
        let mut added = 0u32;
        for _ in current..target_size {
            self.connect_one(connect_request.clone()).await?;
            added += 1;
        }
        Ok(added)
    }

    pub async fn close_all(&self) -> Result<(), EngineError> {
        let ids: Vec<String> = self.session_ids().await;
        for id in ids {
            if let Err(err) = self.connector.disconnect(&id).await {
                warn!(session_id = %id, error = %err, "disconnect failed during pool close");
            }
        }
        self.state.write().await.sessions.clear();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PoolReconnectConfig, SupervisedPoolConfig};
    use async_trait::async_trait;
    use ie_protocol::{
        AttestationBundle, AttestationVerdict, AttestedConnectResponse, CpuTeeAttestation,
        CpuTeeKind, EngineStartupIdentity, GpuTeeAttestation, GpuTeeKind, WorkloadMeasurements,
    };

    struct MockConnector;

    #[async_trait]
    impl EnginePlaneConnector for MockConnector {
        async fn connect(
            &self,
            request: AttestedConnectRequest,
        ) -> Result<ConnectResult, Box<dyn std::error::Error + Send + Sync>> {
            Ok(ConnectResult {
                session_id: request.session_id,
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

    #[tokio::test]
    async fn boots_initial_fraction() {
        let cfg = SupervisedPoolConfig {
            pool_target_size: 4,
            pool_initial_fraction: 0.5,
            supervised: true,
            reconnect: PoolReconnectConfig::default(),
        };
        let pool = Arc::new(SupervisedPool::new(
            cfg,
            "https://gateway.example",
            Arc::new(MockConnector),
            Arc::new(MockUpstream),
        ));
        pool.boot(sample_request()).await.unwrap();
        assert_eq!(pool.session_ids().await.len(), 2);
    }
}
