//! Engine-plane client TLS: an ephemeral identity the hardware vouches for.
//!
//! The engine used to authenticate to the gateway with an operator-provisioned
//! client certificate whose private key sat at
//! `/etc/teechat/tls/engine-plane/client.key.pem` — mode `600` on a rootfs no
//! measurement covers, on a guest that ships standing root SSH, and shared by
//! every engine in the fleet on an 825-day validity. It proved only that
//! someone held a file an operator had once signed.
//!
//! It is now generated here, in memory, at every boot. The digest of the
//! certificate goes into the attestation report's `REPORT_DATA` alongside the
//! epoch keys, so the gateway can require the report to name the certificate
//! presented on the socket. That is a stronger claim than the CA made — it
//! says the key is held by an attested TEE running allowlisted code — and it
//! costs nothing to rotate, because the key dies with the process.
//!
//! The CA certificate is still read from the environment. It is a public trust
//! anchor rather than a secret, and the engine needs it to authenticate the
//! *gateway*, which is the direction this module does not attest.

use std::collections::BTreeMap;

use attested_mtls::pem::{read_pem_maybe, PemKind};
use attested_mtls::sha256_cert_pem;
use chrono::{Datelike, Duration, Utc};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

use crate::error::RuntimeError;
use crate::EnvMap;

const CA_PEM_ENV: &str = "TEECHAT_GATEWAY_ENGINE_TLS_CA_PEM";

/// Certificate validity, in days.
///
/// Nothing on either end validates these dates: the engine does not check its
/// own certificate, and the gateway deliberately does not build a chain (the
/// attestation binding is what authorizes it). The window is set to a
/// conventional value so the certificate looks unremarkable to any middlebox
/// or packet capture. The lifetime that actually matters is the process's.
const CERT_VALIDITY_DAYS: i64 = 397;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineClientTlsMaterial {
    pub ca_cert_pem: String,
    pub client_cert_pem: String,
    pub client_key_pem: String,
    pub client_cert_sha256: String,
}

fn env_to_btree(env: &EnvMap) -> BTreeMap<String, String> {
    env.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
}

/// Self-signed client certificate and key, generated fresh and never written down.
///
/// `subject` is cosmetic — it makes a packet capture or a gateway log readable.
/// Nothing authorizes on it, because a self-signed subject is whatever its
/// holder chose; the report binding is the authorization.
pub fn generate_ephemeral_client_identity(
    subject: &str,
) -> Result<(String, String, String), RuntimeError> {
    let key_pair =
        KeyPair::generate().map_err(|e| RuntimeError::EphemeralTls(format!("keygen: {e}")))?;

    // SANs are not consulted by the gateway, but rcgen requires the parameter
    // and an empty extension is more likely to upset a TLS stack than a name.
    let mut params = CertificateParams::new(vec![subject.to_string()])
        .map_err(|e| RuntimeError::EphemeralTls(format!("params: {e}")))?;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, subject);
    params.distinguished_name = dn;

    let now = Utc::now();
    // Backdate by a day so a gateway whose clock trails ours does not see a
    // certificate from the future during the first minutes after a cutover.
    let start = now - Duration::days(1);
    let end = now + Duration::days(CERT_VALIDITY_DAYS);
    params.not_before = rcgen::date_time_ymd(start.year(), start.month() as u8, start.day() as u8);
    params.not_after = rcgen::date_time_ymd(end.year(), end.month() as u8, end.day() as u8);

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| RuntimeError::EphemeralTls(format!("self-sign: {e}")))?;

    let cert_pem = cert.pem();
    let digest = sha256_cert_pem(&cert_pem)
        .map_err(|e| RuntimeError::AttestedMtls(format!("cert digest: {e}")))?;
    Ok((cert_pem, key_pair.serialize_pem(), digest))
}

/// Engine-plane client TLS material: CA from the environment, identity from memory.
///
/// Call this **once** per process and reuse the result. Each call mints a new
/// key, so a second call would produce a certificate whose digest is not the
/// one bound into the attestation report the gateway is checking against.
pub fn engine_plane_client_tls(
    env: &EnvMap,
    subject: &str,
) -> Result<EngineClientTlsMaterial, RuntimeError> {
    let snapshot = env_to_btree(env);
    let raw = snapshot
        .get(CA_PEM_ENV)
        .map(String::as_str)
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| RuntimeError::AttestedMtls(format!("{CA_PEM_ENV} is required")))?;
    let ca_cert_pem = read_pem_maybe(raw, PemKind::Certificate)
        .map_err(|e| RuntimeError::AttestedMtls(e.to_string()))?;

    let (client_cert_pem, client_key_pem, client_cert_sha256) =
        generate_ephemeral_client_identity(subject)?;
    Ok(EngineClientTlsMaterial {
        ca_cert_pem,
        client_cert_pem,
        client_key_pem,
        client_cert_sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ca_fixture() -> String {
        // Any parseable certificate works: the CA is only stored here, and it
        // is rustls that later rejects a malformed anchor.
        let kp = KeyPair::generate().unwrap();
        CertificateParams::new(vec!["ca.test".to_string()])
            .unwrap()
            .self_signed(&kp)
            .unwrap()
            .pem()
    }

    fn env_with_ca() -> EnvMap {
        let mut env = EnvMap::new();
        env.insert(CA_PEM_ENV.to_string(), ca_fixture());
        env
    }

    #[test]
    fn generates_a_usable_self_signed_identity() {
        let (cert, key, digest) = generate_ephemeral_client_identity("engine-prod-1").unwrap();
        assert!(cert.contains("BEGIN CERTIFICATE"));
        assert!(key.contains("PRIVATE KEY"));
        assert_eq!(digest.len(), 64);
        assert_eq!(digest, sha256_cert_pem(&cert).unwrap());
    }

    #[test]
    fn every_call_mints_a_different_key() {
        // The whole point is that the credential does not outlive the process.
        // If two calls agreed, the identity would be derived from something
        // stable and would be reproducible by whoever else held that input.
        let (cert_a, key_a, digest_a) = generate_ephemeral_client_identity("engine-1").unwrap();
        let (cert_b, key_b, digest_b) = generate_ephemeral_client_identity("engine-1").unwrap();
        assert_ne!(key_a, key_b);
        assert_ne!(cert_a, cert_b);
        assert_ne!(digest_a, digest_b);
    }

    #[test]
    fn digest_is_the_binding_the_gateway_will_check() {
        // The gateway hashes the DER off the wire and compares it to the value
        // the engine put in REPORT_DATA. Both sides must derive it the same
        // way, so this pins ours to the audited crate rather than to a local
        // reimplementation.
        let (cert, _key, digest) = generate_ephemeral_client_identity("engine-1").unwrap();
        assert_eq!(digest, sha256_cert_pem(&cert).unwrap());
    }

    #[test]
    fn carries_the_ca_through_from_the_environment() {
        let env = env_with_ca();
        let material = engine_plane_client_tls(&env, "engine-prod-1").unwrap();
        assert_eq!(
            material.ca_cert_pem.trim(),
            env.get(CA_PEM_ENV).unwrap().trim()
        );
        assert_eq!(
            material.client_cert_sha256,
            sha256_cert_pem(&material.client_cert_pem).unwrap()
        );
    }

    #[test]
    fn the_ca_is_not_the_generated_identity() {
        // Guards against a refactor that self-signs the anchor too, which would
        // make the engine trust a gateway it generated the trust for.
        let env = env_with_ca();
        let material = engine_plane_client_tls(&env, "engine-1").unwrap();
        assert_ne!(material.ca_cert_pem.trim(), material.client_cert_pem.trim());
    }

    #[test]
    fn refuses_to_start_without_a_ca_to_authenticate_the_gateway() {
        // Generating our own identity does not make the gateway's identity
        // optional. Without the anchor the engine would dial an unauthenticated
        // peer and hand it the connect attestation.
        let err = engine_plane_client_tls(&EnvMap::new(), "engine-1").unwrap_err();
        assert!(err.to_string().contains(CA_PEM_ENV));
    }

    #[test]
    fn rejects_a_ca_value_that_is_not_a_certificate() {
        let mut env = EnvMap::new();
        env.insert(CA_PEM_ENV.to_string(), "not-a-pem".to_string());
        assert!(engine_plane_client_tls(&env, "engine-1").is_err());
    }

    #[test]
    fn no_longer_reads_a_client_key_from_the_environment() {
        // Regression guard for the finding this module exists to close: a
        // client key in the environment must not be able to displace the
        // generated one, or an operator could reintroduce the disk key by
        // setting a variable.
        let mut env = env_with_ca();
        env.insert(
            "TEECHAT_GATEWAY_ENGINE_TLS_CLIENT_KEY_PEM".to_string(),
            "/etc/teechat/tls/engine-plane/client.key.pem".to_string(),
        );
        env.insert(
            "TEECHAT_GATEWAY_ENGINE_TLS_CLIENT_CERT_PEM".to_string(),
            "/etc/teechat/tls/engine-plane/client.pem".to_string(),
        );
        let material = engine_plane_client_tls(&env, "engine-1").unwrap();
        assert!(material.client_key_pem.contains("PRIVATE KEY"));
        assert!(!material.client_key_pem.contains("/etc/teechat"));
    }
}
