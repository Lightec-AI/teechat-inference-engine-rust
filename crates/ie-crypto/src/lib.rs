//! Thin wrappers around OPE crates for InferenceEngine decrypt/encrypt paths.
//!
//! Production hybrid PQ E2E lives in `ope-e2e`; envelope framing in `ope-envelope`;
//! transport helpers in `ope-transport`; low-level crypto in `ope-crypto`.
//!
//! TypeScript equivalent: `src/native/ope-ffi.ts`, `src/crypto/provider.ts`,
//! `src/engine/decrypt-handle.ts`.

mod error;

pub use error::CryptoError;

#[cfg(feature = "ope")]
mod envelope;
#[cfg(feature = "ope")]
mod provider;

#[cfg(feature = "ope")]
pub use envelope::{
    envelope_from_json, envelope_to_json, ope_to_protocol_envelope, protocol_to_ope_envelope,
};
#[cfg(feature = "ope")]
pub use provider::{
    client_encrypt_request, create_crypto_provider, is_hybrid_pq_enc, test_mock_engine,
    test_sender_keypair, CryptoProvider, EngineHybridKeypair, MockCryptoProvider,
    RealCryptoProvider, ResponseSession,
};

#[cfg(feature = "ope")]
pub mod ope {
    pub use ope_crypto;
    pub use ope_e2e;
    pub use ope_envelope;
    pub use ope_transport;

    use ie_protocol::OpeE2eDescriptor;
    use ope_e2e::ENC_E2E_HYBRID_PQ;

    /// Map protocol `OpeE2eDescriptor` into `ope-e2e` wire fields for decrypt.
    pub fn fields_from_descriptor(d: &OpeE2eDescriptor) -> ope_e2e::E2eFields {
        ope_e2e::E2eFields {
            kex: d.kex.clone(),
            client_share: d.client_share.clone(),
            mlkem_ciphertext: d
                .mlkem_ciphertext
                .clone()
                .or_else(|| Some(d.engine_mlkem_encap.clone())),
            client_x25519: d
                .client_x25519
                .clone()
                .or_else(|| d.client_share.clone())
                .unwrap_or_default(),
            content_alg: d
                .content_alg
                .clone()
                .unwrap_or_else(|| "chacha20poly1305".into()),
            engine_mlkem_encap: d.engine_mlkem_encap.clone(),
            engine_x25519: d.engine_x25519.clone(),
            server_share: d.server_share.clone(),
        }
    }

    pub fn is_hybrid_pq_enc(enc: &str) -> bool {
        enc == ENC_E2E_HYBRID_PQ
    }
}

/// Crate versions for TCB / attestation reporting.
pub fn dependency_versions() -> [(&'static str, &'static str); 4] {
    [
        ("ope-crypto", "0.1.0"),
        ("ope-envelope", "0.1.0"),
        ("ope-transport", "0.1.0"),
        ("ope-e2e", "0.1.0"),
    ]
}

#[cfg(all(test, feature = "ope"))]
mod tests {
    use super::*;
    use ope_e2e::{
        begin_response_session, decrypt_response_chunk, ClientSession, ENC_E2E_HYBRID_PQ,
    };
    use ope_envelope::{sign_envelope, Envelope};
    use serde_json::json;

    #[test]
    fn hybrid_enc_constant() {
        assert!(is_hybrid_pq_enc(ENC_E2E_HYBRID_PQ));
    }

    #[test]
    fn maps_descriptor_fields() {
        use ie_protocol::OpeE2eDescriptor;
        let d = OpeE2eDescriptor {
            kex: "k".into(),
            client_share: Some("share".into()),
            engine_mlkem_encap: "encap".into(),
            engine_x25519: "x".into(),
            ephemeral_epoch: "epoch".into(),
            content_alg: None,
            mlkem_ciphertext: None,
            client_x25519: Some("x25519".into()),
            server_share: None,
        };
        let f = ope::fields_from_descriptor(&d);
        assert_eq!(f.engine_mlkem_encap, "encap");
        assert_eq!(f.client_x25519, "x25519");
    }

    #[test]
    fn real_provider_request_response_roundtrip() {
        let (secret, engine_pub) = test_mock_engine();
        let provider = RealCryptoProvider::new();
        let handle = provider.register_secret(secret).unwrap();
        let client_session = ClientSession::generate().unwrap();
        let sender = test_sender_keypair();

        let payload = json!({
            "model": "gpt-4.1@openai",
            "messages": [{"role": "user", "content": "secret prompt"}]
        });

        let base = Envelope {
            ope_version: Envelope::VERSION.into(),
            alg: Envelope::ALG_EDDSA.into(),
            enc: Envelope::ENC_NONE.into(),
            kid: "sender-dev".into(),
            recipient: "gateway-dev".into(),
            engine_id: None,
            ts: "2026-05-19T12:00:00Z".into(),
            nonce: "bm9uY2VfZGV2X2UxZQ".into(),
            payload_hash: String::new(),
            payload: None,
            ciphertext: None,
            iv: None,
            aad: None,
            meta: Some(json!({
                "model": "gpt-4.1@openai",
                "tenant": "tenant-a",
                "metering": {"units": 1}
            })),
            e2e: None,
            sig: None,
        };

        let mut protocol_env =
            client_encrypt_request(&engine_pub, &payload, base, Some(&client_session)).unwrap();
        {
            let mut ope = protocol_to_ope_envelope(&protocol_env).unwrap();
            sign_envelope(&mut ope, &sender.secret).unwrap();
            protocol_env = ope_to_protocol_envelope(&ope).unwrap();
        }

        let decrypted = provider.decrypt_request(handle, &protocol_env).unwrap();
        assert_eq!(decrypted, payload);

        let resp = provider.begin_response(handle, &protocol_env).unwrap();
        let chunk0 = provider
            .encrypt_response_chunk(resp.session, 0, b"token1 ")
            .unwrap();
        let chunk1 = provider
            .encrypt_response_chunk(resp.session, 1, b"token2")
            .unwrap();

        let ope = protocol_to_ope_envelope(&protocol_env).unwrap();
        let pt0 = decrypt_response_chunk(
            &ope,
            &client_session,
            &resp.server_share,
            0,
            &chunk0,
        )
        .unwrap();
        let pt1 = decrypt_response_chunk(
            &ope,
            &client_session,
            &resp.server_share,
            1,
            &chunk1,
        )
        .unwrap();
        assert_eq!(pt0, b"token1 ");
        assert_eq!(pt1, b"token2");

        // Also verify begin_response_session path still works against same envelope.
        let (engine_secret, _) = test_mock_engine();
        let (_k, _iv, _server) =
            begin_response_session(&engine_secret, &ope, &client_session).unwrap();

        provider.free_response(resp.session);
        provider.free_engine(handle);
    }

    #[test]
    fn mock_provider_cannot_decrypt() {
        let mock = MockCryptoProvider::new();
        let env = ie_protocol::OpeEnvelope {
            ope_version: "1.0".into(),
            alg: "EdDSA".into(),
            enc: ENC_E2E_HYBRID_PQ.into(),
            kid: "k".into(),
            recipient: "g".into(),
            ts: "t".into(),
            nonce: "n".into(),
            payload_hash: "h".into(),
            engine_id: None,
            meta: None,
            sig: None,
            ciphertext: None,
            iv: None,
            e2e: None,
        };
        assert!(matches!(
            mock.decrypt_request(1, &env),
            Err(CryptoError::MockUnsupported(_))
        ));
        let kp = mock.generate_engine_hybrid("engine-dev", "AAAA").unwrap();
        assert!(kp.handle.is_none());
        assert_eq!(
            kp.hybrid.mlkem_encapsulation_key.len(),
            ie_protocol::MOCK_MLKEM_ENCAP_B64URL_LEN
        );
    }
}
