use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::EngineChallengeError;

pub const ENGINE_CHALLENGE_MAGIC: &str = "teechat-engine-challenge-v1";
pub const ENGINE_CHALLENGE_REPORT_DATA_VERSION: u8 = 1;
pub const ENGINE_CHALLENGE_SCHEMA_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EngineChallengeMeasurement {
    LaunchDigest {
        launch_digest: String,
        image_digest: String,
    },
    Mrenclave {
        mrenclave: String,
    },
}

pub struct EngineChallengeReportDataInput<'a> {
    pub nonce: &'a [u8],
    pub engine_id: &'a str,
    pub epoch_id: &'a str,
    pub not_before: &'a str,
    pub not_after: &'a str,
    pub usage_signing_public_raw: &'a [u8],
    pub mlkem_encap_key_raw: &'a [u8],
    pub x25519_public_raw: &'a [u8],
    pub gpu_evidence_sha256: &'a [u8],
    pub policy_hash: &'a [u8],
    pub measurement: &'a EngineChallengeMeasurement,
}

pub(super) fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub(super) fn decode_hex_32(
    raw: &str,
    label: &'static str,
) -> Result<[u8; 32], EngineChallengeError> {
    let cleaned = raw.trim().to_ascii_lowercase();
    if cleaned.len() != 64 || !cleaned.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(EngineChallengeError::Invalid(label));
    }
    let bytes = hex::decode(cleaned).map_err(|_| EngineChallengeError::Invalid(label))?;
    bytes
        .try_into()
        .map_err(|_| EngineChallengeError::Invalid(label))
}

fn measurement_body(
    measurement: &EngineChallengeMeasurement,
) -> Result<Vec<u8>, EngineChallengeError> {
    match measurement {
        EngineChallengeMeasurement::Mrenclave { mrenclave } => {
            let mut body = Vec::with_capacity(33);
            body.push(0x01);
            body.extend_from_slice(&decode_hex_32(mrenclave, "invalid_mrenclave")?);
            Ok(body)
        }
        EngineChallengeMeasurement::LaunchDigest {
            launch_digest,
            image_digest,
        } => {
            let mut body = Vec::with_capacity(65);
            body.push(0x02);
            body.extend_from_slice(&decode_hex_32(launch_digest, "invalid_launch_digest")?);
            body.extend_from_slice(&decode_hex_32(image_digest, "invalid_image_digest")?);
            Ok(body)
        }
    }
}

/// Build the byte-exact v1 preimage from §5.2 of the ARCH-CHAL design.
pub fn build_engine_challenge_preimage(
    input: &EngineChallengeReportDataInput<'_>,
) -> Result<Vec<u8>, EngineChallengeError> {
    if input.nonce.len() != 32 {
        return Err(EngineChallengeError::Invalid("nonce_must_be_32_bytes"));
    }
    if input.gpu_evidence_sha256.len() != 32 {
        return Err(EngineChallengeError::Invalid("gpu_hash_must_be_32_bytes"));
    }
    if input.policy_hash.len() != 32 {
        return Err(EngineChallengeError::Invalid(
            "policy_hash_must_be_32_bytes",
        ));
    }

    let mut window = Vec::with_capacity(input.not_before.len() + input.not_after.len() + 1);
    window.extend_from_slice(input.not_before.as_bytes());
    window.push(0);
    window.extend_from_slice(input.not_after.as_bytes());

    let measurement = measurement_body(input.measurement)?;
    let mut preimage = Vec::with_capacity(315 + measurement.len());
    preimage.extend_from_slice(ENGINE_CHALLENGE_MAGIC.as_bytes());
    preimage.extend_from_slice(input.nonce);
    preimage.extend_from_slice(&sha256(input.engine_id.as_bytes()));
    preimage.extend_from_slice(&sha256(input.epoch_id.as_bytes()));
    preimage.extend_from_slice(&sha256(&window));
    preimage.extend_from_slice(&sha256(input.usage_signing_public_raw));
    preimage.extend_from_slice(&sha256(input.mlkem_encap_key_raw));
    preimage.extend_from_slice(&sha256(input.x25519_public_raw));
    preimage.extend_from_slice(input.gpu_evidence_sha256);
    preimage.extend_from_slice(input.policy_hash);
    preimage.extend_from_slice(&measurement);
    Ok(preimage)
}

/// SNP REPORT_DATA = SHA-256(preimage) || 32 zero bytes.
pub fn build_engine_challenge_report_data(
    input: &EngineChallengeReportDataInput<'_>,
) -> Result<[u8; 64], EngineChallengeError> {
    let digest = sha256(&build_engine_challenge_preimage(input)?);
    let mut report_data = [0u8; 64];
    report_data[..32].copy_from_slice(&digest);
    Ok(report_data)
}

pub fn encode_nonce_b64_url(nonce: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(nonce)
}

pub fn decode_nonce_b64_url(raw: &str) -> Result<[u8; 32], EngineChallengeError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(raw.trim())
        .map_err(|_| EngineChallengeError::Invalid("invalid_nonce_b64"))?;
    decoded
        .try_into()
        .map_err(|_| EngineChallengeError::Invalid("nonce_must_be_32_bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn launch_measurement() -> EngineChallengeMeasurement {
        EngineChallengeMeasurement::LaunchDigest {
            launch_digest: "a".repeat(64),
            image_digest: "b".repeat(64),
        }
    }

    fn vector_input<'a>(
        nonce: &'a [u8],
        usage: &'a [u8],
        mlkem: &'a [u8],
        x25519: &'a [u8],
        gpu_hash: &'a [u8],
        policy_hash: &'a [u8],
        measurement: &'a EngineChallengeMeasurement,
    ) -> EngineChallengeReportDataInput<'a> {
        EngineChallengeReportDataInput {
            nonce,
            engine_id: "eng-1",
            epoch_id: "ep-1",
            not_before: "2026-08-01T00:00:00.000Z",
            not_after: "2026-08-02T00:00:00.000Z",
            usage_signing_public_raw: usage,
            mlkem_encap_key_raw: mlkem,
            x25519_public_raw: x25519,
            gpu_evidence_sha256: gpu_hash,
            policy_hash,
            measurement,
        }
    }

    #[test]
    fn nonce_base64url_round_trips_without_padding() {
        let nonce = [0xabu8; 32];
        let encoded = encode_nonce_b64_url(&nonce);
        assert!(!encoded.contains('='));
        assert_eq!(decode_nonce_b64_url(&encoded).unwrap(), nonce);
    }

    #[test]
    fn report_data_matches_typescript_reference_vector() {
        let nonce = [1u8; 32];
        let usage = [2u8; 32];
        let mlkem = [3u8; 1184];
        let x25519 = [4u8; 32];
        let gpu_hash = [0u8; 32];
        let policy_hash = [5u8; 32];
        let measurement = launch_measurement();
        let input = vector_input(
            &nonce,
            &usage,
            &mlkem,
            &x25519,
            &gpu_hash,
            &policy_hash,
            &measurement,
        );

        let preimage = build_engine_challenge_preimage(&input).unwrap();
        assert_eq!(preimage.len(), 380);
        let report_data = build_engine_challenge_report_data(&input).unwrap();
        assert_eq!(
            hex::encode(report_data),
            concat!(
                "de0fbdb204520b8d945f7286f4881ddee31f196ca5d0fe34ead2cfae6a272ff2",
                "0000000000000000000000000000000000000000000000000000000000000000"
            )
        );
    }

    #[test]
    fn changing_nonce_changes_the_bound_digest() {
        let usage = [2u8; 32];
        let mlkem = [3u8; 1184];
        let x25519 = [4u8; 32];
        let gpu_hash = [0u8; 32];
        let policy_hash = [5u8; 32];
        let measurement = launch_measurement();
        let nonce_a = [1u8; 32];
        let nonce_b = [9u8; 32];
        let a = build_engine_challenge_report_data(&vector_input(
            &nonce_a,
            &usage,
            &mlkem,
            &x25519,
            &gpu_hash,
            &policy_hash,
            &measurement,
        ))
        .unwrap();
        let b = build_engine_challenge_report_data(&vector_input(
            &nonce_b,
            &usage,
            &mlkem,
            &x25519,
            &gpu_hash,
            &policy_hash,
            &measurement,
        ))
        .unwrap();
        assert_ne!(&a[..32], &b[..32]);
        assert_eq!(&a[32..], &[0u8; 32]);
    }
}
