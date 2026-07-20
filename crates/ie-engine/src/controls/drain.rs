//! Pool drain control — SIGUSR2 + JSON request file.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::cutover::{parse_pool_drain_request_json, PoolDrainRequest};
use crate::pool::{PoolDrainResult, SupervisedPool};

pub fn read_pool_drain_request_file(path: impl AsRef<Path>) -> Result<PoolDrainRequest, String> {
    let raw = fs::read_to_string(path.as_ref()).map_err(|e| e.to_string())?;
    parse_pool_drain_request_json(&raw)
}

pub async fn run_pool_drain_once(
    pool: &SupervisedPool,
    request: &PoolDrainRequest,
) -> Result<PoolDrainResult, crate::EngineError> {
    if let Some(count) = request.count {
        pool.drain_idle_sessions(count).await
    } else {
        pool.drain_idle_pool(request.fraction.unwrap_or(0.5))
            .await
    }
}

pub struct PoolDrainControl {
    pool: Arc<SupervisedPool>,
    request_file: String,
    handling: Mutex<bool>,
}

impl PoolDrainControl {
    pub fn new(pool: Arc<SupervisedPool>, request_file: impl Into<String>) -> Self {
        Self {
            pool,
            request_file: request_file.into(),
            handling: Mutex::new(false),
        }
    }

    pub async fn handle_signal(&self) {
        let mut handling = self.handling.lock().await;
        if *handling {
            return;
        }
        *handling = true;
        drop(handling);

        let result = (async {
            let req = read_pool_drain_request_file(&self.request_file)?;
            let out = run_pool_drain_once(&self.pool, &req)
                .await
                .map_err(|e| e.to_string())?;
            let _ = fs::remove_file(&self.request_file);
            Ok::<_, String>(out)
        })
        .await;

        if let Err(err) = result {
            eprintln!("[engine-pool-drain] failed: {err}");
        }

        *self.handling.lock().await = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn read_pool_drain_request_file_fraction() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("req.json");
        fs::write(&path, r#"{"fraction":0.5}"#).unwrap();
        let req = read_pool_drain_request_file(&path).unwrap();
        assert_eq!(req.fraction, Some(0.5));
    }

    #[test]
    fn read_pool_drain_request_file_count() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("req.json");
        fs::write(&path, r#"{"count":1}"#).unwrap();
        let req = read_pool_drain_request_file(&path).unwrap();
        assert_eq!(req.count, Some(1));
    }
}
