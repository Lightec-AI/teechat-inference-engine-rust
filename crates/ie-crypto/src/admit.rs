//! RB-05: admit signed OPE requests before hybrid decrypt.
//!
//! Chat clients sign envelopes (`recipient: teechat-gateway`). OpenAPI edge
//! envelopes are still unsigned (`sig: None`). Admission modes:
//!
//! - `off` — legacy decrypt only (default when no trust keys).
//! - `signed-only` — `verify_and_open` when `sig` is present; unsigned stays legacy.
//! - `required` — every envelope must pass `verify_and_open` (breaks unsigned OpenAPI).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use ope_crypto::{decode, public_key_from_bytes, PublicKey};
use ope_envelope::{
    verify_and_open, Capability, KeyResolver, MemoryReplayStore, OpenError, OpenOptions,
};
use ie_protocol::OpeEnvelope;

use crate::envelope::protocol_to_ope_envelope;
use crate::CryptoError;

/// How strictly the engine authenticates inbound envelopes (RB-05).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeAdmitMode {
    Off,
    SignedOnly,
    Required,
}

impl EnvelopeAdmitMode {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "off" | "0" | "false" => Some(Self::Off),
            "signed-only" | "signed_only" | "signed" => Some(Self::SignedOnly),
            "required" | "require" | "on" | "1" | "true" => Some(Self::Required),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MapKeyResolver {
    keys: HashMap<String, PublicKey>,
}

impl MapKeyResolver {
    pub fn from_b64url_map(map: &HashMap<String, String>) -> Result<Self, CryptoError> {
        let mut keys = HashMap::new();
        for (kid, pk_b64) in map {
            if kid.trim() == "*" {
                return Err(CryptoError::InvalidKey(
                    "wildcard trust kid '*' is not allowed on the engine".into(),
                ));
            }
            let bytes = decode(pk_b64.trim())
                .map_err(|_| CryptoError::InvalidKey(format!("trust key for kid {kid}")))?;
            let arr: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::InvalidKey(format!("trust key length for kid {kid}")))?;
            let pk = public_key_from_bytes(&arr)
                .map_err(|_| CryptoError::InvalidKey(format!("trust key for kid {kid}")))?;
            keys.insert(kid.clone(), pk);
        }
        Ok(Self { keys })
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

impl KeyResolver for MapKeyResolver {
    fn sender_key(&self, kid: &str) -> Option<PublicKey> {
        self.keys.get(kid).copied()
    }
}

/// Process-local admission policy + replay store.
pub struct EnvelopeAdmitter {
    mode: EnvelopeAdmitMode,
    resolver: MapKeyResolver,
    replay: Arc<MemoryReplayStore>,
    expected_recipient: String,
    max_skew: Duration,
}

impl EnvelopeAdmitter {
    pub fn new(
        mode: EnvelopeAdmitMode,
        resolver: MapKeyResolver,
        expected_recipient: impl Into<String>,
        max_skew: Duration,
    ) -> Self {
        Self {
            mode,
            resolver,
            replay: Arc::new(MemoryReplayStore::new()),
            expected_recipient: expected_recipient.into(),
            max_skew,
        }
    }

    /// Build from env. Prefer `TEECHAT_OPE_ENGINE_TRUST_KEYS`; fall back to
    /// `TEECHAT_OPE_GATEWAY_TRUST_KEYS` so ops can reuse the gateway map.
    ///
    /// `TEECHAT_OPE_ENGINE_VERIFY` = `off` | `signed-only` | `required`.
    /// Default: `signed-only` when trust keys exist, else `off`.
    pub fn from_env(env: &HashMap<String, String>) -> Result<Option<Self>, CryptoError> {
        let keys_json = env
            .get("TEECHAT_OPE_ENGINE_TRUST_KEYS")
            .or_else(|| env.get("TEECHAT_OPE_GATEWAY_TRUST_KEYS"))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let resolver = match keys_json {
            Some(raw) => {
                let map: HashMap<String, String> = serde_json::from_str(&raw)?;
                MapKeyResolver::from_b64url_map(&map)?
            }
            None => MapKeyResolver {
                keys: HashMap::new(),
            },
        };

        let mode = env
            .get("TEECHAT_OPE_ENGINE_VERIFY")
            .and_then(|s| EnvelopeAdmitMode::parse(s))
            .unwrap_or(if resolver.is_empty() {
                EnvelopeAdmitMode::Off
            } else {
                EnvelopeAdmitMode::SignedOnly
            });

        if mode == EnvelopeAdmitMode::Off {
            return Ok(None);
        }
        if resolver.is_empty() {
            return Err(CryptoError::InvalidKey(
                "TEECHAT_OPE_ENGINE_VERIFY requires TEECHAT_OPE_ENGINE_TRUST_KEYS (or GATEWAY_TRUST_KEYS)".into(),
            ));
        }

        let recipient = env
            .get("TEECHAT_OPE_ENGINE_EXPECTED_RECIPIENT")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "teechat-gateway".into());

        let skew_secs = env
            .get("TEECHAT_OPE_ENGINE_MAX_SKEW_SECS")
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(300);

        Ok(Some(Self::new(
            mode,
            resolver,
            recipient,
            Duration::from_secs(skew_secs),
        )))
    }

    pub fn mode(&self) -> EnvelopeAdmitMode {
        self.mode
    }

    /// Admit when policy requires it. Returns `Ok(Some(cap))` after
    /// `verify_and_open`, `Ok(None)` when this envelope is left to legacy decrypt.
    pub fn admit(&self, envelope: &OpeEnvelope) -> Result<Option<Capability>, CryptoError> {
        let has_sig = envelope
            .sig
            .as_ref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);

        match self.mode {
            EnvelopeAdmitMode::Off => Ok(None),
            EnvelopeAdmitMode::SignedOnly if !has_sig => Ok(None),
            EnvelopeAdmitMode::SignedOnly | EnvelopeAdmitMode::Required => {
                let ope = protocol_to_ope_envelope(envelope)?;
                let options = OpenOptions {
                    max_skew: self.max_skew,
                    expected_recipient: Some(self.expected_recipient.clone()),
                    require_routed_model: false,
                    allow_opaque_e2e: true,
                };
                let cap = verify_and_open(&ope, &self.resolver, self.replay.as_ref(), &options)
                    .map_err(map_open_error)?;
                Ok(Some(cap))
            }
        }
    }
}

fn map_open_error(err: OpenError) -> CryptoError {
    CryptoError::Admit(err.code().to_string(), err.to_string())
}

/// Shared process admitter (optional).
static GLOBAL_ADMITTER: std::sync::OnceLock<Option<Arc<EnvelopeAdmitter>>> = std::sync::OnceLock::new();

pub fn install_global_admitter(admitter: Option<Arc<EnvelopeAdmitter>>) {
    let _ = GLOBAL_ADMITTER.set(admitter);
}

pub fn global_admitter() -> Option<Arc<EnvelopeAdmitter>> {
    GLOBAL_ADMITTER.get().and_then(|o| o.clone())
}

/// Parse trust-key JSON for tests.
pub fn parse_trust_keys_json(raw: &str) -> Result<MapKeyResolver, CryptoError> {
    let map: HashMap<String, String> = serde_json::from_str(raw)?;
    MapKeyResolver::from_b64url_map(&map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ope_crypto::{encode, mock_keypair_from_seed, sign};
    use ope_envelope::{canonical::signing_bytes, Envelope};

    #[test]
    fn signed_only_skips_unsigned() {
        let kp = mock_keypair_from_seed(&[7u8; 32]);
        let mut keys = HashMap::new();
        keys.insert("guest".into(), encode(&kp.public.to_bytes()));
        let resolver = MapKeyResolver::from_b64url_map(&keys).unwrap();
        let admitter = EnvelopeAdmitter::new(
            EnvelopeAdmitMode::SignedOnly,
            resolver,
            "teechat-gateway",
            Duration::from_secs(3600),
        );
        let env = OpeEnvelope {
            ope_version: "1.0".into(),
            alg: "EdDSA".into(),
            enc: "e2e-hybrid-pq".into(),
            kid: "guest".into(),
            recipient: "teechat-gateway".into(),
            ts: "2026-08-05T12:00:00Z".into(),
            nonce: "n1".into(),
            payload_hash: "ph".into(),
            engine_id: Some("engine-1".into()),
            meta: None,
            sig: None,
            ciphertext: Some("ct".into()),
            iv: Some("iv".into()),
            e2e: None,
        };
        assert!(admitter.admit(&env).unwrap().is_none());
    }

    #[test]
    fn required_rejects_unknown_kid() {
        let kp = mock_keypair_from_seed(&[7u8; 32]);
        let mut keys = HashMap::new();
        keys.insert("guest".into(), encode(&kp.public.to_bytes()));
        let resolver = MapKeyResolver::from_b64url_map(&keys).unwrap();
        let admitter = EnvelopeAdmitter::new(
            EnvelopeAdmitMode::Required,
            resolver,
            "teechat-gateway",
            Duration::from_secs(3600 * 24 * 365),
        );

        let mut ope = Envelope {
            ope_version: "1.0".into(),
            alg: Envelope::ALG_EDDSA.into(),
            enc: Envelope::ENC_E2E_HYBRID_PQ.into(),
            kid: "other".into(),
            recipient: "teechat-gateway".into(),
            ts: "2026-08-05T12:00:00Z".into(),
            nonce: "n-unknown".into(),
            payload_hash: encode(&[0u8; 32]),
            engine_id: Some("engine-1".into()),
            meta: None,
            sig: None,
            ciphertext: Some("ct".into()),
            iv: Some("iv".into()),
            aad: None,
            e2e: Some(serde_json::json!({
                "kex": "x25519+mlkem768",
                "client_share": "cs",
                "mlkem_ciphertext": "mc",
                "client_x25519": "cx",
                "engine_mlkem_encap": "em",
                "engine_x25519": "ex"
            })),
            payload: None,
        };
        let msg = signing_bytes(&ope).unwrap();
        let sig = sign(&kp.secret, &msg);
        ope.sig = Some(encode(&sig));
        let proto: OpeEnvelope =
            serde_json::from_value(serde_json::to_value(&ope).unwrap()).unwrap();
        let err = admitter.admit(&proto).unwrap_err();
        match err {
            CryptoError::Admit(code, _) => assert_eq!(code, "ope_unknown_kid"),
            other => panic!("unexpected {other:?}"),
        }
    }
}
