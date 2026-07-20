//! Engine ephemeral epoch creation (port of `engine/epoch.ts`).

use std::sync::Arc;

use chrono::{Duration, Utc};
use ed25519_dalek::{Signer, SigningKey};
use ie_crypto::{CryptoProvider, EngineHybridKeypair};
use ie_protocol::{AttestationBundle, EngineEphemeralRegisterRequest, EngineHybridPublic};
use ope_crypto::decode;

use crate::ops::ephemeral_signing_bytes;
use crate::EngineError;

#[derive(Clone)]
pub struct EngineEpoch {
    pub epoch_id: String,
    pub hybrid: EngineHybridPublic,
    pub ephemeral_request: EngineEphemeralRegisterRequest,
    pub not_before: String,
    pub not_after: String,
    pub handle: Option<u64>,
    pub provider: Arc<dyn CryptoProvider>,
}

pub struct CreateEngineEpochArgs<'a> {
    pub engine_id: &'a str,
    pub ed25519_public_b64: &'a str,
    pub signing_key: &'a SigningKey,
    pub attestation: Option<AttestationBundle>,
    pub epoch_id: Option<String>,
    pub ttl_ms: Option<u64>,
    pub provider: Arc<dyn CryptoProvider>,
}

pub fn create_engine_epoch(args: CreateEngineEpochArgs<'_>) -> Result<EngineEpoch, EngineError> {
    let now = Utc::now();
    let now_ms = now.timestamp_millis() as u64;
    let not_before = now.to_rfc3339();
    let ttl = args.ttl_ms.unwrap_or(86_400_000);
    let not_after = (now + Duration::milliseconds(ttl as i64)).to_rfc3339();
    let epoch_id = args
        .epoch_id
        .unwrap_or_else(|| format!("epoch-{now_ms}"));

    let EngineHybridKeypair { hybrid, handle } = args
        .provider
        .generate_engine_hybrid(args.engine_id, args.ed25519_public_b64)
        .map_err(|e| EngineError::Epoch(e.to_string()))?;

    let signing_bytes = ephemeral_signing_bytes(
        args.engine_id,
        &epoch_id,
        &not_after,
        &hybrid,
    );
    let signature = args.signing_key.sign(&signing_bytes);
    let identity_signature = ope_crypto::encode(signature.to_bytes().as_slice());

    let ephemeral_request = EngineEphemeralRegisterRequest {
        engine_id: args.engine_id.to_string(),
        epoch_id: epoch_id.clone(),
        not_before: not_before.clone(),
        not_after: not_after.clone(),
        hybrid: hybrid.clone(),
        identity_signature,
        attestation: args.attestation.clone(),
    };

    Ok(EngineEpoch {
        epoch_id,
        hybrid,
        ephemeral_request,
        not_before,
        not_after,
        handle,
        provider: args.provider,
    })
}

pub fn dispose_engine_epoch(epoch: &EngineEpoch) {
    if let Some(handle) = epoch.handle {
        epoch.provider.free_engine(handle);
    }
}

/// Decode a 32-byte Ed25519 seed/private from base64url public material's paired secret env.
/// Decode a 32-byte Ed25519 seed from base64url (tests / dev key load).
#[allow(dead_code)]
pub fn signing_key_from_seed_b64(seed_b64: &str) -> Result<SigningKey, EngineError> {
    let bytes = decode(seed_b64).map_err(|_| EngineError::Epoch("invalid signing seed".into()))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| EngineError::Epoch("signing seed length".into()))?;
    Ok(SigningKey::from_bytes(&arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ie_crypto::MockCryptoProvider;
    use ope_crypto::mock_keypair_from_seed;
    use ope_crypto::DEV_VECTOR_001_SEED;

    #[test]
    fn create_engine_epoch_roundtrip() {
        let provider = Arc::new(MockCryptoProvider::new());
        let kp = mock_keypair_from_seed(&DEV_VECTOR_001_SEED);
        let pub_b64 = ope_crypto::encode(kp.public.to_bytes().as_slice());
        let epoch = create_engine_epoch(CreateEngineEpochArgs {
            engine_id: "eng",
            ed25519_public_b64: &pub_b64,
            signing_key: &kp.secret,
            attestation: None,
            epoch_id: Some("epoch-a".into()),
            ttl_ms: Some(60_000),
            provider,
        })
        .unwrap();
        assert_eq!(epoch.epoch_id, "epoch-a");
        assert_eq!(epoch.ephemeral_request.engine_id, "eng");
        assert!(epoch.handle.is_none());
    }
}
