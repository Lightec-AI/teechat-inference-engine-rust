//! Gateway migration control — SIGUSR1 + JSON request file.

use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::time::{sleep, Instant};

use crate::gateway_migration::{parse_gateway_migration_request_json, GatewayMigrationRequest};
use crate::pool::{GatewayMigrationResult, SupervisedPool};

const MIGRATION_RETRY_DELAY_MS: u64 = 2_000;
const MIGRATION_RETRY_MAX_MS: u64 = 360_000;

pub fn read_gateway_migration_request_file(path: impl AsRef<Path>) -> Result<GatewayMigrationRequest, String> {
    let raw = fs::read_to_string(path.as_ref()).map_err(|e| e.to_string())?;
    parse_gateway_migration_request_json(&raw)
}

fn migration_target_reached(result: &GatewayMigrationResult) -> bool {
    !result.blocked && result.on_target >= result.target_count
}

pub struct GatewayMigrationControl {
    pool: Arc<SupervisedPool>,
    request_file: String,
    handling: Mutex<bool>,
}

impl GatewayMigrationControl {
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
            let req = read_gateway_migration_request_file(&self.request_file)?;
            let deadline = Instant::now() + Duration::from_millis(MIGRATION_RETRY_MAX_MS);
            let mut result = self
                .pool
                .migrate_gateway_pool(&req.target_url, req.fraction)
                .await
                .map_err(|e| e.to_string())?;
            while !migration_target_reached(&result) && Instant::now() < deadline {
                sleep(Duration::from_millis(MIGRATION_RETRY_DELAY_MS)).await;
                result = self
                    .pool
                    .migrate_gateway_pool(&req.target_url, req.fraction)
                    .await
                    .map_err(|e| e.to_string())?;
            }
            let _ = fs::remove_file(&self.request_file);
            Ok::<GatewayMigrationResult, String>(result)
        })
        .await;

        if let Err(err) = result {
            eprintln!("[engine-gateway-migration] failed: {err}");
        }

        *self.handling.lock().await = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn reads_gateway_migration_request_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("req.json");
        fs::write(
            &path,
            r#"{"target_url":"https://10.0.0.1:8790","fraction":0.5}"#,
        )
        .unwrap();
        let req = read_gateway_migration_request_file(&path).unwrap();
        assert_eq!(req.target_url, "https://10.0.0.1:8790");
        assert!((req.fraction - 0.5).abs() < f64::EPSILON);
    }
}
