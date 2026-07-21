//! Pull-worker registry owned by [`crate::pool::SupervisedPool`] (TS SessionSlot.pullWorker parity).

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::{Mutex, RwLock};
use tracing::warn;

use crate::plane::PullWorkerHandle;

pub type PullWorkerStartFuture =
    Pin<Box<dyn Future<Output = Result<PullWorkerHandle, String>> + Send>>;
pub type PullWorkerStartFn = Arc<dyn Fn(String) -> PullWorkerStartFuture + Send + Sync>;

/// Optional callback when the live session id set changes (epoch rotator list).
pub type SessionsChangedFn = Arc<dyn Fn(Vec<String>) + Send + Sync>;

#[derive(Default)]
pub struct PullWorkerRegistry {
    workers: Mutex<HashMap<String, PullWorkerHandle>>,
    start_fn: RwLock<Option<PullWorkerStartFn>>,
}

impl PullWorkerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn set_start_fn(&self, start_fn: Option<PullWorkerStartFn>) {
        *self.start_fn.write().await = start_fn;
    }

    pub async fn has_worker(&self, session_id: &str) -> bool {
        self.workers.lock().await.contains_key(session_id)
    }

    pub async fn is_busy(&self, session_id: &str) -> bool {
        self.workers
            .lock()
            .await
            .get(session_id)
            .map(|w| w.is_busy())
            .unwrap_or(false)
    }

    /// Stop pull worker before disconnect (TS `drainSlotAt` order).
    pub async fn stop_session(&self, session_id: &str) {
        if let Some(worker) = self.workers.lock().await.remove(session_id) {
            worker.stop();
        }
    }

    /// Start a pull worker after connect / migrate (no-op if starter unset — unit tests).
    pub async fn ensure_started(&self, session_id: &str) -> Result<(), String> {
        {
            let workers = self.workers.lock().await;
            if workers.contains_key(session_id) {
                return Ok(());
            }
        }
        let start = self.start_fn.read().await.clone();
        let Some(start) = start else {
            return Ok(());
        };
        let handle = start(session_id.to_string()).await?;
        self.workers
            .lock()
            .await
            .insert(session_id.to_string(), handle);
        Ok(())
    }

    pub async fn stop_all(&self) {
        let mut workers = self.workers.lock().await;
        for (_, worker) in workers.drain() {
            worker.stop();
        }
    }

    pub async fn session_ids(&self) -> Vec<String> {
        self.workers.lock().await.keys().cloned().collect()
    }
}

/// Helper used by pool when a starter fails after connect.
pub fn warn_pull_worker_start(session_id: &str, err: &str) {
    warn!(session_id = %session_id, error = %err, "pull worker start failed");
}
