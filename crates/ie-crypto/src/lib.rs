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
            mlkem_ciphertext: Some(d.engine_mlkem_encap.clone()),
            client_x25519: d.client_share.clone().unwrap_or_default(),
            content_alg: d.content_alg.clone().unwrap_or_else(|| "aes-256-gcm".into()),
            engine_mlkem_encap: d.engine_mlkem_encap.clone(),
            engine_x25519: d.engine_x25519.clone(),
            server_share: None,
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
    use super::ope::{fields_from_descriptor, is_hybrid_pq_enc};
    use ie_protocol::OpeE2eDescriptor;
    use ope_e2e::ENC_E2E_HYBRID_PQ;

    #[test]
    fn hybrid_enc_constant() {
        assert!(is_hybrid_pq_enc(ENC_E2E_HYBRID_PQ));
    }

    #[test]
    fn maps_descriptor_fields() {
        let d = OpeE2eDescriptor {
            kex: "k".into(),
            client_share: Some("share".into()),
            engine_mlkem_encap: "encap".into(),
            engine_x25519: "x".into(),
            ephemeral_epoch: "epoch".into(),
            content_alg: None,
        };
        let f = fields_from_descriptor(&d);
        assert_eq!(f.engine_mlkem_encap, "encap");
        assert_eq!(f.client_x25519, "share");
    }
}
