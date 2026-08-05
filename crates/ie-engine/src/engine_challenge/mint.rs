use std::collections::HashMap;

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::{SecondsFormat, Utc};
use ie_attestation::{
    encode_sev_snp_quote_wrapper, load_cpu_tee_endorsement_from_env,
    request_sev_snp_attestation_report, QuoteClaims, SevSnpQuoteWrapper,
};
use ie_protocol::{CpuTeeEndorsement, CpuTeeKind, WorkloadMeasurements};
use serde::{Deserialize, Serialize};

use super::report_data::{decode_hex_32, sha256};
use super::{
    build_engine_challenge_report_data, decode_nonce_b64_url, encode_nonce_b64_url,
    EngineChallengeError, EngineChallengeMeasurement, EngineChallengeReportDataInput,
    ENGINE_CHALLENGE_REPORT_DATA_VERSION, ENGINE_CHALLENGE_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineChallengeWireRequest {
    pub nonce_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineChallengeEpoch {
    pub epoch_id: String,
    pub not_before: String,
    pub not_after: String,
    pub mlkem_encapsulation_key: String,
    pub x25519_public: String,
    pub usage_signing_public: String,
}

impl From<&crate::epoch::EngineEpoch> for EngineChallengeEpoch {
    fn from(epoch: &crate::epoch::EngineEpoch) -> Self {
        Self {
            epoch_id: epoch.epoch_id.clone(),
            not_before: epoch.not_before.clone(),
            not_after: epoch.not_after.clone(),
            mlkem_encapsulation_key: epoch.hybrid.mlkem_encapsulation_key.clone(),
            x25519_public: epoch.hybrid.x25519_public.clone(),
            usage_signing_public: epoch.usage_signing_public_b64.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineChallengeEngineResponse {
    pub engine_id: String,
    pub build_version: String,
    pub measurement: EngineChallengeMeasurement,
    pub policy_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineChallengeCpuResponse {
    pub quote_format: String,
    pub quote_b64: String,
    pub endorsement: CpuTeeEndorsement,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineChallengeGpuResponse {
    pub evidence_format: String,
    pub evidence_b64: String,
    pub evidence_sha256: String,
    pub collected_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineChallengeWireResponse {
    pub schema_version: u8,
    pub report_data_version: u8,
    pub engine: EngineChallengeEngineResponse,
    pub epoch: EngineChallengeEpoch,
    pub challenge_nonce_b64: String,
    pub cpu: EngineChallengeCpuResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu: Option<EngineChallengeGpuResponse>,
}

pub struct MintEngineChallengeArgs<'a> {
    pub request: &'a EngineChallengeWireRequest,
    pub engine_id: &'a str,
    pub build_version: &'a str,
    pub policy_hash_hex: &'a str,
    pub measurement: &'a EngineChallengeMeasurement,
    pub epoch: &'a EngineChallengeEpoch,
    pub gpu_evidence_b64: Option<&'a str>,
    pub gpu_collected_at: Option<&'a str>,
    pub env: &'a HashMap<String, String>,
}

fn decode_wire_base64(raw: &str, label: &'static str) -> Result<Vec<u8>, EngineChallengeError> {
    let trimmed = raw.trim();
    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        if let Ok(bytes) = engine.decode(trimmed) {
            return Ok(bytes);
        }
    }
    Err(EngineChallengeError::Invalid(label))
}

fn gpu_hash(
    evidence_b64: Option<&str>,
) -> Result<([u8; 32], Option<(String, Vec<u8>)>), EngineChallengeError> {
    let Some(evidence) = evidence_b64.map(str::trim).filter(|raw| !raw.is_empty()) else {
        return Ok(([0u8; 32], None));
    };
    let raw = decode_wire_base64(evidence, "invalid_gpu_evidence_b64")?;
    Ok((sha256(&raw), Some((evidence.to_string(), raw))))
}

fn mint_engine_challenge_response_with<F>(
    args: &MintEngineChallengeArgs<'_>,
    mint_report: F,
) -> Result<EngineChallengeWireResponse, EngineChallengeError>
where
    F: FnOnce(&[u8; 64]) -> Result<Vec<u8>, EngineChallengeError>,
{
    let nonce = decode_nonce_b64_url(&args.request.nonce_b64)?;
    if args
        .request
        .epoch_id
        .as_deref()
        .is_some_and(|requested| requested != args.epoch.epoch_id)
    {
        return Err(EngineChallengeError::EpochMismatch);
    }

    let endorsement = load_cpu_tee_endorsement_from_env(args.env)
        .ok_or(EngineChallengeError::EndorsementUnavailable)?;
    let (gpu_evidence_sha256, gpu_evidence) = gpu_hash(args.gpu_evidence_b64)?;
    let policy_hash = decode_hex_32(args.policy_hash_hex, "invalid_policy_hash")?;
    let usage_signing_public_raw = decode_wire_base64(
        &args.epoch.usage_signing_public,
        "invalid_usage_signing_public",
    )?;
    let mlkem_encap_key_raw = decode_wire_base64(
        &args.epoch.mlkem_encapsulation_key,
        "invalid_mlkem_encapsulation_key",
    )?;
    let x25519_public_raw = decode_wire_base64(&args.epoch.x25519_public, "invalid_x25519_public")?;
    let report_data = build_engine_challenge_report_data(&EngineChallengeReportDataInput {
        nonce: &nonce,
        engine_id: args.engine_id,
        epoch_id: &args.epoch.epoch_id,
        not_before: &args.epoch.not_before,
        not_after: &args.epoch.not_after,
        usage_signing_public_raw: &usage_signing_public_raw,
        mlkem_encap_key_raw: &mlkem_encap_key_raw,
        x25519_public_raw: &x25519_public_raw,
        gpu_evidence_sha256: &gpu_evidence_sha256,
        policy_hash: &policy_hash,
        measurement: args.measurement,
    })?;
    let report = mint_report(&report_data)?;
    let issued_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let zero_hash = "0".repeat(64);
    let wrapper = SevSnpQuoteWrapper {
        v: 2,
        kind: "sev-snp".into(),
        report_b64: STANDARD.encode(report),
        report_data_b64: STANDARD.encode(report_data),
        claims: QuoteClaims {
            v: 1,
            kind: CpuTeeKind::SevSnp,
            ed25519_public: String::new(),
            tls_client_cert_sha256: zero_hash.clone(),
            engine: WorkloadMeasurements {
                version: args.build_version.to_string(),
                binary_sha256: zero_hash.clone(),
            },
            vllm: WorkloadMeasurements {
                version: "0".into(),
                binary_sha256: zero_hash,
            },
            ope: None,
            attested_mtls: None,
            launch_digest: None,
            epoch: None,
            issued_at: issued_at.clone(),
        },
    };

    let gpu = gpu_evidence.map(|(evidence_b64, raw)| EngineChallengeGpuResponse {
        evidence_format: "nvattest_v1".into(),
        evidence_b64,
        evidence_sha256: hex::encode(sha256(&raw)),
        collected_at: args
            .gpu_collected_at
            .map(str::to_string)
            .unwrap_or(issued_at),
    });

    Ok(EngineChallengeWireResponse {
        schema_version: ENGINE_CHALLENGE_SCHEMA_VERSION,
        report_data_version: ENGINE_CHALLENGE_REPORT_DATA_VERSION,
        engine: EngineChallengeEngineResponse {
            engine_id: args.engine_id.to_string(),
            build_version: args.build_version.to_string(),
            measurement: args.measurement.clone(),
            policy_hash: args.policy_hash_hex.trim().to_ascii_lowercase(),
        },
        epoch: args.epoch.clone(),
        challenge_nonce_b64: encode_nonce_b64_url(&nonce),
        cpu: EngineChallengeCpuResponse {
            quote_format: "snp_report".into(),
            quote_b64: encode_sev_snp_quote_wrapper(&wrapper),
            endorsement,
        },
        gpu,
    })
}

pub fn mint_engine_challenge_response(
    args: &MintEngineChallengeArgs<'_>,
) -> Result<EngineChallengeWireResponse, EngineChallengeError> {
    mint_engine_challenge_response_with(args, |report_data| {
        request_sev_snp_attestation_report(report_data, args.env).map_err(Into::into)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ie_attestation::parse_sev_snp_quote_wrapper;

    fn epoch() -> EngineChallengeEpoch {
        EngineChallengeEpoch {
            epoch_id: "ep-1".into(),
            not_before: "2026-08-01T00:00:00.000Z".into(),
            not_after: "2026-08-02T00:00:00.000Z".into(),
            mlkem_encapsulation_key: STANDARD.encode([1u8; 32]),
            x25519_public: STANDARD.encode([2u8; 32]),
            usage_signing_public: STANDARD.encode([3u8; 32]),
        }
    }

    fn measurement() -> EngineChallengeMeasurement {
        EngineChallengeMeasurement::LaunchDigest {
            launch_digest: "a".repeat(64),
            image_digest: "b".repeat(64),
        }
    }

    #[test]
    fn mints_wire_response_with_injected_report_and_endorsement() {
        let nonce = encode_nonce_b64_url(&[7u8; 32]);
        let request = EngineChallengeWireRequest {
            nonce_b64: nonce.clone(),
            epoch_id: None,
        };
        let epoch = epoch();
        let measurement = measurement();
        let env = HashMap::from([
            ("TEECHAT_SNP_VCEK_DER_B64".into(), STANDARD.encode(b"vcek")),
            ("TEECHAT_SNP_ASK_DER_B64".into(), STANDARD.encode(b"ask")),
            ("TEECHAT_SNP_ARK_DER_B64".into(), STANDARD.encode(b"ark")),
        ]);
        let policy_hash = "c".repeat(64);
        let gpu_evidence = STANDARD.encode(b"gpu evidence");
        let args = MintEngineChallengeArgs {
            request: &request,
            engine_id: "eng-1",
            build_version: "0.15.0",
            policy_hash_hex: &policy_hash,
            measurement: &measurement,
            epoch: &epoch,
            gpu_evidence_b64: Some(&gpu_evidence),
            gpu_collected_at: Some("2026-08-01T03:00:00.000Z"),
            env: &env,
        };
        let response = mint_engine_challenge_response_with(&args, |report_data| {
            let mut report = b"SNP".to_vec();
            report.extend_from_slice(report_data);
            Ok(report)
        })
        .expect("response");

        assert_eq!(response.challenge_nonce_b64, nonce);
        assert_eq!(response.schema_version, 1);
        assert_eq!(response.cpu.endorsement.vcek_der_b64, "dmNlaw==");
        assert_eq!(
            response.gpu.as_ref().unwrap().evidence_sha256,
            hex::encode(sha256(b"gpu evidence"))
        );
        let wrapper = parse_sev_snp_quote_wrapper(&response.cpu.quote_b64).expect("quote wrapper");
        assert_eq!(wrapper.claims.engine.version, "0.15.0");
        assert_eq!(STANDARD.decode(wrapper.report_data_b64).unwrap().len(), 64);
    }

    #[test]
    fn rejects_a_named_epoch_mismatch_before_minting() {
        let request = EngineChallengeWireRequest {
            nonce_b64: encode_nonce_b64_url(&[7u8; 32]),
            epoch_id: Some("ep-other".into()),
        };
        let epoch = epoch();
        let measurement = measurement();
        let env = HashMap::from([("TEECHAT_SNP_VCEK_DER_B64".into(), STANDARD.encode(b"vcek"))]);
        let policy_hash = "c".repeat(64);
        let args = MintEngineChallengeArgs {
            request: &request,
            engine_id: "eng-1",
            build_version: "0.15.0",
            policy_hash_hex: &policy_hash,
            measurement: &measurement,
            epoch: &epoch,
            gpu_evidence_b64: None,
            gpu_collected_at: None,
            env: &env,
        };
        let error = mint_engine_challenge_response_with(&args, |_| {
            panic!("must not mint a report for the wrong epoch")
        })
        .unwrap_err();
        assert!(matches!(error, EngineChallengeError::EpochMismatch));
    }
}
