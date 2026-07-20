//! Install runtime pool controls (SIGUSR1/2 + file watchers).

mod drain;
mod migrate;
mod paths;
mod scale;
mod status;

pub use drain::{read_pool_drain_request_file, PoolDrainControl};
pub use migrate::{read_gateway_migration_request_file, GatewayMigrationControl};
pub use paths::{
    default_gateway_migration_file, default_pool_drain_file, default_pool_scale_file,
    default_pool_status_file, resolve_control_file_path,
};
pub use scale::{read_pool_scale_request_file, PoolScaleControl};
pub use status::{
    build_pool_status_snapshot, write_pool_status_file, EnginePoolStatusSnapshot,
    PoolStatusControl, ENGINE_POOL_STATUS_SCHEMA,
};

use std::collections::HashMap;
use std::sync::Arc;

use tokio::signal::unix::{signal, SignalKind};
use tokio::task::JoinHandle;

use crate::pool::SupervisedPool;

pub struct InstalledControls {
    pub drain: Arc<PoolDrainControl>,
    pub scale: Arc<PoolScaleControl>,
    pub status: Arc<PoolStatusControl>,
    pub migrate: Arc<GatewayMigrationControl>,
    _tasks: Vec<JoinHandle<()>>,
}

pub async fn install_engine_controls(
    pool: Arc<SupervisedPool>,
    engine_id: &str,
    env: &HashMap<String, String>,
) -> Result<InstalledControls, std::io::Error> {
    let drain = Arc::new(PoolDrainControl::new(
        Arc::clone(&pool),
        default_pool_drain_file(env),
    ));
    let scale = Arc::new(PoolScaleControl::new(
        Arc::clone(&pool),
        default_pool_scale_file(env),
    ));
    let status = Arc::new(PoolStatusControl::new(
        Arc::clone(&pool),
        engine_id,
        default_pool_status_file(env),
        1_000,
    ));
    let migrate = Arc::new(GatewayMigrationControl::new(
        Arc::clone(&pool),
        default_gateway_migration_file(env),
    ));

    scale.start_polling().await;
    status.start().await;

    let mut tasks = Vec::new();

    let drain_task = {
        let drain = Arc::clone(&drain);
        tokio::spawn(async move {
            let mut sig = signal(SignalKind::user_defined2()).expect("SIGUSR2");
            loop {
                sig.recv().await;
                drain.handle_signal().await;
            }
        })
    };
    tasks.push(drain_task);

    let migrate_task = {
        let migrate = Arc::clone(&migrate);
        tokio::spawn(async move {
            let mut sig = signal(SignalKind::user_defined1()).expect("SIGUSR1");
            loop {
                sig.recv().await;
                migrate.handle_signal().await;
            }
        })
    };
    tasks.push(migrate_task);

    Ok(InstalledControls {
        drain,
        scale,
        status,
        migrate,
        _tasks: tasks,
    })
}
