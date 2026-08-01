//! Engine ephemeral epoch creation (port of `engine/epoch.ts`).

use std::sync::Arc;

use chrono::{Duration, SecondsFormat, Utc};
use ed25519_dalek::{Signer, SigningKey};
use ie_attestation::QuoteEpochClaims;
use ie_crypto::{CryptoProvider, EngineHybridKeypair};
use ie_protocol::{AttestationBundle, EngineEphemeralRegisterRequest, EngineHybridPublic};
use ope_crypto::decode;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::ops::ephemeral_signing_bytes;
use crate::EngineError;

/// Mints hardware evidence over an epoch's own key material.
///
/// A closure rather than a direct call so the epoch layer stays free of the
/// attestation backend, and so tests can mint deterministic evidence without a
/// `/dev/sev-guest`. Returning `None` means "no evidence available on this
/// platform"; the caller then falls back to the connect bundle.
pub type EpochEvidenceMinter =
    Arc<dyn Fn(&QuoteEpochClaims) -> Option<AttestationBundle> + Send + Sync>;

#[derive(Clone)]
pub struct EngineEpoch {
    pub epoch_id: String,
    pub hybrid: EngineHybridPublic,
    pub ephemeral_request: EngineEphemeralRegisterRequest,
    pub not_before: String,
    pub not_after: String,
    pub handle: Option<u64>,
    pub provider: Arc<dyn CryptoProvider>,
    /// Signs usage reports for this epoch only, so metering trust expires with
    /// the epoch instead of living as long as the process (RB-52).
    pub usage_signing_key: Arc<SigningKey>,
    pub usage_signing_public_b64: String,
}

pub struct CreateEngineEpochArgs<'a> {
    pub engine_id: &'a str,
    pub ed25519_public_b64: &'a str,
    pub signing_key: &'a SigningKey,
    pub attestation: Option<AttestationBundle>,
    pub mint_epoch_evidence: Option<EpochEvidenceMinter>,
    pub epoch_id: Option<String>,
    pub ttl_ms: Option<u64>,
    pub provider: Arc<dyn CryptoProvider>,
}

fn generate_usage_signing_key() -> SigningKey {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    SigningKey::from_bytes(&seed)
}

pub fn create_engine_epoch(args: CreateEngineEpochArgs<'_>) -> Result<EngineEpoch, EngineError> {
    let now = Utc::now();
    let now_ms = now.timestamp_millis() as u64;
    // Millis + Z — same shape as `issued_at` in the SNP wrapper. chrono's
    // default `to_rfc3339()` emits `+00:00` with nanoseconds; those strings are
    // what go into REPORT_DATA bind-v2, so any later rewrite to Z-millis
    // (gateway "edge compatibility") silently breaks client verification.
    let not_before = now.to_rfc3339_opts(SecondsFormat::Millis, true);
    let ttl = args.ttl_ms.unwrap_or(86_400_000);
    let not_after = (now + Duration::milliseconds(ttl as i64))
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    // Millisecond granularity alone collides when two epochs are minted in the
    // same tick, and a gateway that holds one epoch id to one set of keys
    // rejects the second one (RB-42).
    let epoch_id = args.epoch_id.unwrap_or_else(|| {
        let mut suffix = [0u8; 4];
        OsRng.fill_bytes(&mut suffix);
        format!("epoch-{now_ms}-{}", hex::encode(suffix))
    });

    let EngineHybridKeypair { hybrid, handle } = args
        .provider
        .generate_engine_hybrid(args.engine_id, args.ed25519_public_b64)
        .map_err(|e| EngineError::Epoch(e.to_string()))?;

    let usage_signing_key = generate_usage_signing_key();
    let usage_signing_public_b64 =
        ope_crypto::encode(usage_signing_key.verifying_key().as_bytes().as_slice());

    let epoch_claims = QuoteEpochClaims {
        engine_id: args.engine_id.to_string(),
        epoch_id: epoch_id.clone(),
        not_before: not_before.clone(),
        not_after: not_after.clone(),
        mlkem_encapsulation_key: hybrid.mlkem_encapsulation_key.clone(),
        x25519_public: hybrid.x25519_public.clone(),
        usage_signing_public: usage_signing_public_b64.clone(),
    };
    let attestation = args
        .mint_epoch_evidence
        .as_ref()
        .and_then(|mint| mint(&epoch_claims))
        .or_else(|| args.attestation.clone());

    // Retained for gateways that predate epoch-bound evidence; receivers that
    // accept bind v2 no longer consult it (RB-52).
    let signing_bytes = ephemeral_signing_bytes(args.engine_id, &epoch_id, &not_after, &hybrid);
    let signature = args.signing_key.sign(&signing_bytes);
    let identity_signature = ope_crypto::encode(signature.to_bytes().as_slice());

    let ephemeral_request = EngineEphemeralRegisterRequest {
        engine_id: args.engine_id.to_string(),
        epoch_id: epoch_id.clone(),
        not_before: not_before.clone(),
        not_after: not_after.clone(),
        hybrid: hybrid.clone(),
        identity_signature,
        attestation,
    };

    Ok(EngineEpoch {
        epoch_id,
        hybrid,
        ephemeral_request,
        not_before,
        not_after,
        handle,
        provider: args.provider,
        usage_signing_key: Arc::new(usage_signing_key),
        usage_signing_public_b64,
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
            mint_epoch_evidence: None,
            epoch_id: Some("epoch-a".into()),
            ttl_ms: Some(60_000),
            provider,
        })
        .unwrap();
        assert_eq!(epoch.epoch_id, "epoch-a");
        assert_eq!(epoch.ephemeral_request.engine_id, "eng");
        assert!(epoch.handle.is_none());
        // Bind-v2 hashes these strings verbatim; keep them Z-millis like issued_at.
        assert!(
            epoch.not_before.ends_with('Z'),
            "not_before must be Z-millis, got {}",
            epoch.not_before
        );
        assert!(
            !epoch.not_before.contains('+'),
            "not_before must not use +00:00 form, got {}",
            epoch.not_before
        );
        assert_eq!(epoch.not_before, epoch.ephemeral_request.not_before);
        assert_eq!(epoch.not_after, epoch.ephemeral_request.not_after);
    }
}
