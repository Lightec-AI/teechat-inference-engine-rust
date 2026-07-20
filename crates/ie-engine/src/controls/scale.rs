//! Pool scale control — file poll (Linux has no SIGUSR3).

use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time;

use crate::cutover::{parse_pool_scale_request_json, PoolScaleRequest};
use crate::pool::{PoolScaleResult, SupervisedPool};

pub fn read_pool_scale_request_file(path: impl AsRef<Path>) -> Result<PoolScaleRequest, String> {
    let raw = fs::read_to_string(path.as_ref()).map_err(|e| e.to_string())?;
    parse_pool_scale_request_json(&raw)
}

pub struct PoolScaleControl {
    pool: Arc<SupervisedPool>,
    request_file: String,
    handling: Mutex<bool>,
    poll: Mutex<Option<JoinHandle<()>>>,
}

impl PoolScaleControl {
    pub fn new(pool: Arc<SupervisedPool>, request_file: impl Into<String>) -> Self {
        Self {
            pool,
            request_file: request_file.into(),
            handling: Mutex::new(false),
            poll: Mutex::new(None),
        }
    }

    pub async fn start_polling(self: &Arc<Self>) {
        let this = Arc::clone(self);
        let handle = tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(2));
            loop {
                interval.tick().await;
                if fs::read_to_string(&this.request_file).is_ok() {
                    this.run_once().await;
                }
            }
        });
        *self.poll.lock().await = Some(handle);
    }

    pub async fn run_once(&self) {
        let mut handling = self.handling.lock().await;
        if *handling {
            return;
        }
        *handling = true;
        drop(handling);

        let result = (async {
            let req = read_pool_scale_request_file(&self.request_file)?;
            let template = self
                .pool
                .connect_template()
                .await
                .ok_or_else(|| "no connect template; boot pool before scale".to_string())?;
            let added = self
                .pool
                .scale_to(req.target_size, template)
                .await
                .map_err(|e| e.to_string())?;
            let _ = fs::remove_file(&self.request_file);
            Ok::<PoolScaleResult, String>(PoolScaleResult {
                added,
                total: self.pool.live_session_count().await,
                target_size: req.target_size,
                blocked: false,
                reason: None,
            })
        })
        .await;

        if let Err(err) = result {
            eprintln!("[engine-pool-scale] failed: {err}");
        }

        *self.handling.lock().await = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn reads_pool_scale_request_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("req.json");
        fs::write(&path, r#"{"target_size":2}"#).unwrap();
        let req = read_pool_scale_request_file(&path).unwrap();
        assert_eq!(req.target_size, 2);
    }
}
