//! Ephemeral epoch creation and rotation (port of `engine/epoch*.ts`).

mod engine_epoch;
mod gpu_idle_recollect;
mod policy;
mod rotating_decryptor;
mod rotator;

pub use engine_epoch::{
    create_engine_epoch, dispose_engine_epoch, CreateEngineEpochArgs, EngineEpoch,
    EpochEvidenceMinter,
};
pub use gpu_idle_recollect::{
    new_gpu_evidence_cache, read_gpu_evidence_cache, spawn_gpu_evidence_idle_recollect,
    write_gpu_evidence_cache, GpuEvidenceCache, GpuIdleRecollectConfig,
};
pub use policy::{
    compute_epoch_rotate_at_ms, epoch_rotation_lead_ms_from_env, epoch_rotation_policy_from_env,
    epoch_ttl_ms_from_policy, EpochRotationPolicy,
};
pub use rotating_decryptor::RotatingEpochDecryptor;
pub use rotator::{
    EphemeralPoster, EpochRotatedCallback, EpochRotator, EpochRotatorOptions, EpochRotatorSession,
};
