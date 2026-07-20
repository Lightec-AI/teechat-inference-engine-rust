use thiserror::Error;

#[derive(Debug, Error)]
pub enum AttestationError {
    #[error("missing engine runtime measurement: set TEECHAT_ENGINE_BINARY_SHA256 / TEECHAT_IE_RUNTIME_SHA256 or RELEASE_MANIFEST.json ieRuntimeSha256")]
    MissingEngineSha,
    #[error("missing vLLM measurement: set TEECHAT_VLLM_BINARY_SHA256 or TEECHAT_VLLM_BINARY_PATH")]
    MissingVllmSha,
    #[error("failed to read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse JSON at {path}: {source}")]
    Json {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("invalid tcb pins: {reason}")]
    InvalidTcbPins { reason: String },
    #[error("/dev/sev-guest is not available")]
    SevGuestUnavailable,
    #[error("failed to invoke {bin}: {source}")]
    ToolInvoke {
        bin: String,
        #[source]
        source: std::io::Error,
    },
    #[error("tool {bin} failed")]
    ToolFailed { bin: String },
    #[error("invalid TEECHAT_SNP_GUEST_BIN (allow snpguest or /usr/bin|/usr/local/bin/snpguest): {0}")]
    InvalidSnpGuestBin(String),
    #[error("invalid TEECHAT_NVATTEST_BIN (allow nvattest or /usr/bin|/usr/local/bin/nvattest): {0}")]
    InvalidNvattestBin(String),
    #[error("gpu_cc_mode_off")]
    GpuCcModeOff,
}
