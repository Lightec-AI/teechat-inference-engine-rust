//! Ephemeral epoch creation and rotation (port of `engine/epoch*.ts`).

mod engine_epoch;
mod policy;
mod rotator;
mod rotating_decryptor;

pub use engine_epoch::{create_engine_epoch, dispose_engine_epoch, CreateEngineEpochArgs, EngineEpoch};
pub use policy::{
    compute_epoch_rotate_at_ms, epoch_rotation_lead_ms_from_env, epoch_rotation_policy_from_env,
    epoch_ttl_ms_from_policy, EpochRotationPolicy,
};
pub use rotator::{EphemeralPoster, EpochRotatedCallback, EpochRotator, EpochRotatorSession};
pub use rotating_decryptor::RotatingEpochDecryptor;
