//! ARCH-CHAL engine attestation challenge.
//!
//! This is separate from `plane::challenge`, which only handles the
//! gateway-connect nonce echo.

mod mint;
mod report_data;

pub use mint::{
    mint_engine_challenge_response, EngineChallengeCpuResponse, EngineChallengeEngineResponse,
    EngineChallengeEpoch, EngineChallengeGpuResponse, EngineChallengeWireRequest,
    EngineChallengeWireResponse, MintEngineChallengeArgs,
};
pub use report_data::{
    build_engine_challenge_preimage, build_engine_challenge_report_data, decode_nonce_b64_url,
    encode_nonce_b64_url, EngineChallengeMeasurement, EngineChallengeReportDataInput,
    ENGINE_CHALLENGE_MAGIC, ENGINE_CHALLENGE_REPORT_DATA_VERSION, ENGINE_CHALLENGE_SCHEMA_VERSION,
};

#[derive(Debug, thiserror::Error)]
pub enum EngineChallengeError {
    #[error("{0}")]
    Invalid(&'static str),
    #[error("epoch_mismatch")]
    EpochMismatch,
    #[error("endorsement_unavailable")]
    EndorsementUnavailable,
    #[error("attestation_report: {0}")]
    Attestation(#[from] ie_attestation::AttestationError),
}
