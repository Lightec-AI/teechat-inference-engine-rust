//! Engine-plane client TLS via `attested-mtls` (port of `runtime/engine-tls.ts`).

use std::collections::BTreeMap;

use attested_mtls::tls::{load_engine_client_tls_from_env, EngineClientTlsMaterial as AmTlsMaterial};

use crate::error::RuntimeError;
use crate::EnvMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineClientTlsMaterial {
    pub ca_cert_pem: String,
    pub client_cert_pem: String,
    pub client_key_pem: String,
    pub client_cert_sha256: String,
}

impl From<AmTlsMaterial> for EngineClientTlsMaterial {
    fn from(m: AmTlsMaterial) -> Self {
        Self {
            ca_cert_pem: m.ca_cert_pem,
            client_cert_pem: m.client_cert_pem,
            client_key_pem: m.client_key_pem,
            client_cert_sha256: m.client_cert_sha256,
        }
    }
}

fn env_to_btree(env: &EnvMap) -> BTreeMap<String, String> {
    env.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
}

/// Load engine-plane client TLS material from env using the audited `attested-mtls` crate.
pub fn load_engine_plane_client_tls(env: &EnvMap) -> Result<EngineClientTlsMaterial, RuntimeError> {
    let snapshot = env_to_btree(env);
    load_engine_client_tls_from_env(&snapshot, None)
        .map(EngineClientTlsMaterial::from)
        .map_err(|e| RuntimeError::AttestedMtls(e.to_string()))
}
