//! Remint engine attestation on reconnect / scale / migrate (port of `attestation-refresh.ts`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ie_protocol::AttestationBundle;

use crate::error::AttestationError;
use crate::sev_snp::build_engine_attestation_bundle;

/// Inputs for minting a fresh CPU/GPU attestation bundle.
#[derive(Debug, Clone)]
pub struct EngineAttestationRefreshContext {
    pub ed25519_public: String,
    pub tls_client_cert_sha256: String,
    pub root: PathBuf,
    pub env: HashMap<String, String>,
}

pub type EngineAttestationRefresher =
    Arc<dyn Fn() -> Result<AttestationBundle, AttestationError> + Send + Sync>;

/// Mint a fresh SNP/mock attestation bundle (new quote each call).
pub fn create_engine_attestation_refresher(
    ctx: EngineAttestationRefreshContext,
) -> EngineAttestationRefresher {
    let ed25519_public = ctx.ed25519_public;
    let tls_hash = ctx.tls_client_cert_sha256.to_ascii_lowercase();
    let root = ctx.root;
    let env = ctx.env;
    Arc::new(move || {
        build_engine_attestation_bundle(&env, Path::new(&root), &ed25519_public, &tls_hash, None)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn refresher_mints_distinct_issued_at() {
        let dir = TempDir::new().unwrap();
        let mut env = HashMap::new();
        env.insert("TEECHAT_ENGINE_STUB".into(), "1".into());
        env.insert(
            "TEECHAT_IE_RUNTIME_SHA256".into(),
            "a1b2c3d4e5f6789012345678abcdef9012345678abcdef9012345678abcdef90".into(),
        );
        env.insert(
            "TEECHAT_VLLM_BINARY_SHA256".into(),
            "b2c3d4e5f6789012345678abcdef9012345678abcdef9012345678abcdef9012".into(),
        );
        let refresh = create_engine_attestation_refresher(EngineAttestationRefreshContext {
            ed25519_public: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            tls_client_cert_sha256: "0".repeat(64),
            root: dir.path().to_path_buf(),
            env,
        });
        let a = refresh().expect("first");
        std::thread::sleep(std::time::Duration::from_millis(5));
        let b = refresh().expect("second");
        // Mock quotes embed claims JSON — issued_at should differ across remints.
        assert_ne!(a.cpu_tee.quote, b.cpu_tee.quote);
    }
}
