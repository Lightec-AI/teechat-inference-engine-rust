//! Supervised engine plane pool skeleton (port of `engine/supervised-pool.ts`).

mod config;
mod error;
mod pool;
mod traits;

pub use config::{PoolReconnectConfig, SupervisedPoolConfig};
pub use error::EngineError;
pub use pool::{PoolSession, SupervisedPool, SupervisedPoolHandle};
pub use traits::{EnginePlaneConnector, InferenceUpstream, ConnectResult, InferResult};
