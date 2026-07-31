//! InferenceEngine runtime: env loading and attested-mtls TLS material.

mod env;
mod error;
mod tls;

pub use env::{env_map_from_process, load_engine_env_files, EnvMap};
pub use error::RuntimeError;
pub use tls::{
    engine_plane_client_tls, generate_ephemeral_client_identity, EngineClientTlsMaterial,
};
