use thiserror::Error;

#[derive(Debug, Error)]
pub enum PlaneError {
    #[error("tls: {0}")]
    Tls(String),
    #[error("h2: {0}")]
    H2(String),
    #[error("attested connect failed: {status} {body}")]
    ConnectHttp { status: u16, body: String },
    #[error("gateway_attestation_missing")]
    GatewayAttestationMissing,
    #[error("gateway_challenge_nonce_required")]
    GatewayChallengeNonceRequired,
    #[error("gateway_challenge_nonce_mismatch")]
    GatewayChallengeNonceMismatch,
    #[error("gateway_challenge_nonce_not_bound")]
    GatewayChallengeNonceNotBound,
    #[error("gateway_platform_attestation_failed: {reason}")]
    GatewayPlatformAttestationFailed { reason: String },
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("timeout waiting for ready_to_close")]
    DisconnectTimeout,
    #[error("unknown session_id: {0}")]
    UnknownSession(String),
    #[error("invalid gateway url: {0}")]
    InvalidUrl(String),
}
