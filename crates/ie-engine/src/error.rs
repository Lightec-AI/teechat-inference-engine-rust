use thiserror::Error;

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("pool connect failed: {0}")]
    Connect(String),
    #[error("pool at capacity ({current}/{target})")]
    AtCapacity { current: usize, target: usize },
    #[error("pool circuit open until {until_ms}")]
    CircuitOpen { until_ms: u64 },
    #[error("inference upstream error: {0}")]
    Infer(String),
}
