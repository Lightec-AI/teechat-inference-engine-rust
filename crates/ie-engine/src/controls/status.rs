//! Live pool status publisher (port of `pool-status-control.ts`).

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use serde::Serialize;
use tokio::task::JoinHandle;
use tokio::time;

use crate::pool::SupervisedPool;

pub const ENGINE_POOL_STATUS_SCHEMA: &str = "teechat-engine-pool-status/v1";

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EnginePoolStatusSnapshot {
    pub schema: String,
    pub engine_id: String,
    pub live_sessions: u32,
    pub sessions_by_gateway_url: HashMap<String, u32>,
    pub updated_at: String,
}

pub fn build_pool_status_snapshot(
    engine_id: &str,
    live_sessions: u32,
    sessions_by_gateway_url: HashMap<String, u32>,
) -> EnginePoolStatusSnapshot {
    EnginePoolStatusSnapshot {
        schema: ENGINE_POOL_STATUS_SCHEMA.into(),
        engine_id: engine_id.to_string(),
        live_sessions,
        sessions_by_gateway_url,
        updated_at: Utc::now().to_rfc3339(),
    }
}

pub fn write_pool_status_file(path: impl AsRef<Path>, snapshot: &EnginePoolStatusSnapshot) -> std::io::Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
    let body = serde_json::to_string(snapshot).expect("status json") + "\n";
    fs::write(&tmp, body)?;
    fs::rename(tmp, path)
}

pub struct PoolStatusControl {
    pool: Arc<SupervisedPool>,
    engine_id: String,
    status_file: PathBuf,
    interval_ms: u64,
    timer: tokio::sync::Mutex<Option<JoinHandle<()>>>,
}

impl PoolStatusControl {
    pub fn new(
        pool: Arc<SupervisedPool>,
        engine_id: impl Into<String>,
        status_file: impl Into<PathBuf>,
        interval_ms: u64,
    ) -> Self {
        Self {
            pool,
            engine_id: engine_id.into(),
            status_file: status_file.into(),
            interval_ms: interval_ms.max(250),
            timer: tokio::sync::Mutex::new(None),
        }
    }

    pub async fn start(self: &Arc<Self>) {
        self.publish_once().await;
        let this = Arc::clone(self);
        let handle = tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_millis(this.interval_ms));
            loop {
                interval.tick().await;
                this.publish_once().await;
            }
        });
        *self.timer.lock().await = Some(handle);
    }

    pub async fn publish_once(&self) {
        let live = self.pool.live_session_count().await;
        let by_url = self.pool.sessions_by_gateway_url().await;
        let snapshot = build_pool_status_snapshot(&self.engine_id, live, by_url);
        if let Err(err) = write_pool_status_file(&self.status_file, &snapshot) {
            eprintln!("[engine-pool-status] failed: {err}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_pool_status_snapshot_schema() {
        let snap = build_pool_status_snapshot("eng", 2, HashMap::new());
        assert_eq!(snap.schema, ENGINE_POOL_STATUS_SCHEMA);
        assert_eq!(snap.live_sessions, 2);
    }
}
