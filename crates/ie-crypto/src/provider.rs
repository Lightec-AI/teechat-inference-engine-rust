//! Crypto provider seam over hybrid E2E (port of `src/crypto/provider.ts`).
//!
//! Real provider uses `ope-e2e` in-process (no FFI handle table). Mock provider
//! generates correctly sized public material for registry flows only.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ie_protocol::{EngineHybridPublic, OpeEnvelope, MOCK_MLKEM_ENCAP_B64URL_LEN};
use ope_crypto::{encode, mock_keypair_from_seed, public_key_from_bytes, Keypair};
use ope_e2e::{
    begin_response_session_from_share, decrypt_request, encrypt_response_chunk,
    mock_engine_from_seed, EngineIdentity, EngineStaticSecret, ENC_E2E_HYBRID_PQ, DEV_ENGINE_SEED,
};
use ope_envelope::Envelope;
use rand::RngCore;
use serde_json::Value;

use crate::envelope::{ope_to_protocol_envelope, protocol_to_ope_envelope};
use crate::CryptoError;

#[derive(Debug, Clone)]
pub struct EngineHybridKeypair {
    pub hybrid: EngineHybridPublic,
    /// Opaque epoch handle (`None` for mock).
    pub handle: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct ResponseSession {
    pub session: u64,
    pub server_share: String,
}

struct LiveResponse {
    key: [u8; 32],
    iv: [u8; 12],
}

/// Engine + client hybrid E2E operations.
pub trait CryptoProvider: Send + Sync {
    fn mode(&self) -> &'static str;

    fn generate_engine_hybrid(
        &self,
        engine_id: &str,
        ed25519_public_b64: &str,
    ) -> Result<EngineHybridKeypair, CryptoError>;

    fn decrypt_request(&self, handle: u64, envelope: &OpeEnvelope) -> Result<Value, CryptoError>;

    fn begin_response(
        &self,
        handle: u64,
        request_envelope: &OpeEnvelope,
    ) -> Result<ResponseSession, CryptoError>;

    fn encrypt_response_chunk(
        &self,
        session: u64,
        seq: u32,
        plaintext: &[u8],
    ) -> Result<String, CryptoError>;

    fn free_response(&self, session: u64);

    fn free_engine(&self, handle: u64);
}

struct RealState {
    next_handle: u64,
    engines: HashMap<u64, Arc<EngineStaticSecret>>,
    responses: HashMap<u64, LiveResponse>,
    next_session: u64,
}

/// Production crypto provider backed by `ope-e2e`.
pub struct RealCryptoProvider {
    state: Mutex<RealState>,
}

impl RealCryptoProvider {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(RealState {
                next_handle: 1,
                engines: HashMap::new(),
                responses: HashMap::new(),
                next_session: 1,
            }),
        }
    }

    /// Install a pre-built epoch secret (e.g. from `mock_engine_from_seed` in tests).
    pub fn register_secret(&self, secret: EngineStaticSecret) -> Result<u64, CryptoError> {
        let mut st = self.state.lock().expect("crypto state");
        let handle = st.next_handle;
        st.next_handle += 1;
        st.engines.insert(handle, Arc::new(secret));
        Ok(handle)
    }

    pub fn hybrid_from_identity(identity: &EngineIdentity) -> EngineHybridPublic {
        EngineHybridPublic {
            kex: identity.kex.clone(),
            mlkem_encapsulation_key: identity.mlkem_encapsulation_key.clone(),
            x25519_public: identity.x25519_public.clone(),
        }
    }
}

impl Default for RealCryptoProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoProvider for RealCryptoProvider {
    fn mode(&self) -> &'static str {
        "real"
    }

    fn generate_engine_hybrid(
        &self,
        engine_id: &str,
        ed25519_public_b64: &str,
    ) -> Result<EngineHybridKeypair, CryptoError> {
        let ed_bytes = ope_crypto::decode(ed25519_public_b64)
            .map_err(|_| CryptoError::InvalidKey("ed25519_public".into()))?;
        let ed_arr: [u8; 32] = ed_bytes
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKey("ed25519_public length".into()))?;
        let ed = public_key_from_bytes(&ed_arr)
            .map_err(|_| CryptoError::InvalidKey("ed25519_public".into()))?;
        let (secret, identity) = EngineStaticSecret::generate(engine_id, ed)?;
        let handle = self.register_secret(secret)?;
        Ok(EngineHybridKeypair {
            handle: Some(handle),
            hybrid: Self::hybrid_from_identity(&identity),
        })
    }

    fn decrypt_request(&self, handle: u64, envelope: &OpeEnvelope) -> Result<Value, CryptoError> {
        let secret = {
            let st = self.state.lock().expect("crypto state");
            st.engines
                .get(&handle)
                .cloned()
                .ok_or(CryptoError::UnknownHandle(handle))?
        };
        let ope = protocol_to_ope_envelope(envelope)?;
        Ok(decrypt_request(&ope, secret.as_ref())?)
    }

    fn begin_response(
        &self,
        handle: u64,
        request_envelope: &OpeEnvelope,
    ) -> Result<ResponseSession, CryptoError> {
        let secret = {
            let st = self.state.lock().expect("crypto state");
            st.engines
                .get(&handle)
                .cloned()
                .ok_or(CryptoError::UnknownHandle(handle))?
        };
        let ope = protocol_to_ope_envelope(request_envelope)?;
        let client_share = ope
            .e2e
            .as_ref()
            .and_then(|v| v.get("client_share"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| CryptoError::E2eMsg("missing e2e.client_share".into()))?;
        let (key, iv, server) =
            begin_response_session_from_share(secret.as_ref(), &ope, client_share)?;
        let server_share = encode(&server.bytes);
        let mut st = self.state.lock().expect("crypto state");
        let session = st.next_session;
        st.next_session += 1;
        st.responses.insert(session, LiveResponse { key, iv });
        Ok(ResponseSession {
            session,
            server_share,
        })
    }

    fn encrypt_response_chunk(
        &self,
        session: u64,
        seq: u32,
        plaintext: &[u8],
    ) -> Result<String, CryptoError> {
        let st = self.state.lock().expect("crypto state");
        let live = st
            .responses
            .get(&session)
            .ok_or(CryptoError::UnknownSession(session))?;
        Ok(encrypt_response_chunk(&live.key, &live.iv, seq, plaintext)?)
    }

    fn free_response(&self, session: u64) {
        let mut st = self.state.lock().expect("crypto state");
        st.responses.remove(&session);
    }

    fn free_engine(&self, handle: u64) {
        let mut st = self.state.lock().expect("crypto state");
        st.engines.remove(&handle);
    }
}

/// Development-only provider: random public material, no decrypt/encrypt.
pub struct MockCryptoProvider;

impl MockCryptoProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MockCryptoProvider {
    fn default() -> Self {
        Self::new()
    }
}

fn mock_mlkem_encap() -> String {
    let mut raw = vec![0u8; (MOCK_MLKEM_ENCAP_B64URL_LEN * 3).div_ceil(4)];
    rand::thread_rng().fill_bytes(&mut raw);
    let mut s = encode(&raw);
    s.truncate(MOCK_MLKEM_ENCAP_B64URL_LEN);
    s
}

impl CryptoProvider for MockCryptoProvider {
    fn mode(&self) -> &'static str {
        "mock"
    }

    fn generate_engine_hybrid(
        &self,
        _engine_id: &str,
        _ed25519_public_b64: &str,
    ) -> Result<EngineHybridKeypair, CryptoError> {
        let mut x25519 = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut x25519);
        Ok(EngineHybridKeypair {
            handle: None,
            hybrid: EngineHybridPublic {
                kex: EngineIdentity::KEX_X25519_MLKEM768.into(),
                mlkem_encapsulation_key: mock_mlkem_encap(),
                x25519_public: encode(&x25519),
            },
        })
    }

    fn decrypt_request(&self, _handle: u64, _envelope: &OpeEnvelope) -> Result<Value, CryptoError> {
        Err(CryptoError::MockUnsupported("decryptRequest".into()))
    }

    fn begin_response(
        &self,
        _handle: u64,
        _request_envelope: &OpeEnvelope,
    ) -> Result<ResponseSession, CryptoError> {
        Err(CryptoError::MockUnsupported("beginResponse".into()))
    }

    fn encrypt_response_chunk(
        &self,
        _session: u64,
        _seq: u32,
        _plaintext: &[u8],
    ) -> Result<String, CryptoError> {
        Err(CryptoError::MockUnsupported("encryptResponseChunk".into()))
    }

    fn free_response(&self, _session: u64) {}

    fn free_engine(&self, _handle: u64) {}
}

/// Resolve provider mode from env (`TEECHAT_CRYPTO=real|mock`), defaulting to real when OPE is available.
pub fn create_crypto_provider(prefer_mock: bool) -> Arc<dyn CryptoProvider> {
    if prefer_mock {
        Arc::new(MockCryptoProvider::new())
    } else {
        Arc::new(RealCryptoProvider::new())
    }
}

/// Helper: encrypt a client request to an engine identity (tests / golden vectors).
pub fn client_encrypt_request(
    engine_identity: &EngineIdentity,
    payload: &Value,
    mut base: Envelope,
    client_session: Option<&ope_e2e::ClientSession>,
) -> Result<OpeEnvelope, CryptoError> {
    ope_e2e::encrypt_request(&mut base, engine_identity, payload, client_session)?;
    ope_to_protocol_envelope(&base)
}

pub fn is_hybrid_pq_enc(enc: &str) -> bool {
    enc == ENC_E2E_HYBRID_PQ
}

/// Deterministic test engine (same seed as `ope-e2e` roundtrip).
pub fn test_mock_engine() -> (EngineStaticSecret, EngineIdentity) {
    mock_engine_from_seed(&DEV_ENGINE_SEED)
}

pub fn test_sender_keypair() -> Keypair {
    mock_keypair_from_seed(&ope_crypto::DEV_VECTOR_001_SEED)
}
