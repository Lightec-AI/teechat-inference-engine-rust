use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("attested-mtls error: {0}")]
    AttestedMtls(String),
    #[error("ephemeral engine-plane identity: {0}")]
    EphemeralTls(String),
    #[error("io error reading {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}
