use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("attested-mtls error: {0}")]
    AttestedMtls(String),
    #[error("io error reading {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}
