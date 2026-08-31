use async_trait::async_trait;
use ie_attestation::{
    parse_mock_cpu_quote, parse_sev_snp_quote_wrapper, verify_platform_attestation_bundle,
    AttestationPolicy, PlatformAttestationBind, PlatformAttestationPolicy,
    ProductionCpuQuoteVerifier,
};
use ie_protocol::{AttestationBundle, AttestedConnectResponse};

use super::error::PlaneError;

fn normalize_tls_leaf(value: &str) -> Option<String> {
    let hex = value.trim().to_ascii_lowercase();
    if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(hex)
    } else {
        None
    }
}

fn gateway_quote_tls_leaf(bundle: &AttestationBundle) -> Result<String, PlaneError> {
    if let Some(wrapper) = parse_sev_snp_quote_wrapper(&bundle.cpu_tee.quote) {
        return Ok(wrapper
            .claims
            .tls_client_cert_sha256
            .trim()
            .to_ascii_lowercase());
    }
    if let Some(claims) = parse_mock_cpu_quote(&bundle.cpu_tee.quote) {
        return Ok(claims.tls_client_cert_sha256.trim().to_ascii_lowercase());
    }
    Err(PlaneError::GatewayPlatformAttestationFailed {
        reason: "tls_cert_claims_unreadable".into(),
    })
}

fn assert_gateway_tls_leaf(
    bundle: &AttestationBundle,
    peer_server_cert_sha256: &str,
) -> Result<(), PlaneError> {
    let expected =
        normalize_tls_leaf(peer_server_cert_sha256).ok_or(PlaneError::GatewayTlsCertMismatch)?;
    let quoted = gateway_quote_tls_leaf(bundle)?;
    if quoted.is_empty() {
        return Err(PlaneError::GatewayTlsCertUnbound);
    }
    if quoted != expected {
        return Err(PlaneError::GatewayTlsCertMismatch);
    }
    Ok(())
}

/// Optional SEC-029 gateway platform attestation verify.
#[async_trait]
pub trait GatewayAttestationVerifier: Send + Sync {
    async fn verify_connect_response(
        &self,
        response: &AttestedConnectResponse,
        expected_nonce: &str,
        peer_server_cert_sha256: &str,
    ) -> Result<(), PlaneError>;
}

/// No-op verifier — **dev/stub only**. Never default this for live gateway dials.
pub struct NullGatewayAttestationVerifier;

#[async_trait]
impl GatewayAttestationVerifier for NullGatewayAttestationVerifier {
    async fn verify_connect_response(
        &self,
        _response: &AttestedConnectResponse,
        _expected_nonce: &str,
        _peer_server_cert_sha256: &str,
    ) -> Result<(), PlaneError> {
        Ok(())
    }
}

/// Fail-closed verifier: requires gateway attestation + challenge nonce echo,
/// and when the CPU quote is a SEV-SNP wrapper, checks `report_data` binding.
pub struct NonceEchoGatewayAttestationVerifier;

#[async_trait]
impl GatewayAttestationVerifier for NonceEchoGatewayAttestationVerifier {
    async fn verify_connect_response(
        &self,
        response: &AttestedConnectResponse,
        expected_nonce: &str,
        _peer_server_cert_sha256: &str,
    ) -> Result<(), PlaneError> {
        let Some(bundle) = response.gateway_attestation.as_ref() else {
            return Err(PlaneError::GatewayAttestationMissing);
        };
        let Some(echo) = response.gateway_challenge_nonce.as_deref() else {
            return Err(PlaneError::GatewayChallengeNonceNotBound);
        };
        let Some(norm) = super::challenge::normalize_gateway_connect_challenge_nonce(echo) else {
            return Err(PlaneError::GatewayChallengeNonceMismatch);
        };
        if norm != expected_nonce {
            return Err(PlaneError::GatewayChallengeNonceMismatch);
        }

        // Best-effort SNP report_data bind when quote is a parseable wrapper.
        if let Some(wrapper) = ie_attestation::parse_sev_snp_quote_wrapper(&bundle.cpu_tee.quote) {
            if !ie_attestation::verify_wrapper_report_data(&wrapper, Some(expected_nonce)) {
                return Err(PlaneError::GatewayChallengeNonceNotBound);
            }
        }

        Ok(())
    }
}

/// Full SEC-029 verifier: nonce echo + platform policy + bundle hash/ed25519 bind
/// (parity with TS `verifyPlatformAttestationBundle`).
///
/// RB-07: uses [`ProductionCpuQuoteVerifier`] — not the mock platform path.
/// Prod release dial must not call the mock convenience wrapper.
pub struct PlatformPolicyGatewayAttestationVerifier {
    pub engine_policy: AttestationPolicy,
    pub platform_policy: PlatformAttestationPolicy,
    pub bind: PlatformAttestationBind,
}

#[async_trait]
impl GatewayAttestationVerifier for PlatformPolicyGatewayAttestationVerifier {
    async fn verify_connect_response(
        &self,
        response: &AttestedConnectResponse,
        expected_nonce: &str,
        peer_server_cert_sha256: &str,
    ) -> Result<(), PlaneError> {
        // Nonce + SNP report_data first (same as NonceEcho).
        NonceEchoGatewayAttestationVerifier
            .verify_connect_response(response, expected_nonce, peer_server_cert_sha256)
            .await?;

        let bundle = response
            .gateway_attestation
            .as_ref()
            .expect("nonce echo verified attestation present");
        assert_gateway_tls_leaf(bundle, peer_server_cert_sha256)?;

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let verdict = verify_platform_attestation_bundle(
            bundle,
            &self.engine_policy,
            &self.platform_policy,
            &self.bind,
            now_ms,
            &ProductionCpuQuoteVerifier,
        );
        if !verdict.ok {
            return Err(PlaneError::GatewayPlatformAttestationFailed {
                reason: verdict.reason.unwrap_or_else(|| "unknown".into()),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ie_protocol::{
        AttestationBundle, AttestationVerdict, CpuTeeAttestation, CpuTeeKind, GpuTeeAttestation,
        GpuTeeKind, WorkloadMeasurements,
    };

    fn sample_bundle() -> AttestationBundle {
        AttestationBundle {
            cpu_tee: CpuTeeAttestation {
                kind: CpuTeeKind::SevSnp,
                quote: "q".into(),
                verdict: AttestationVerdict::Pass,
                policy_id: "p".into(),
                endorsement: None,
            },
            gpu_tee: GpuTeeAttestation {
                kind: GpuTeeKind::NvCc,
                evidence: "g".into(),
                verdict: AttestationVerdict::Pass,
            },
            vllm: WorkloadMeasurements {
                version: "v".into(),
                binary_sha256: "b".repeat(64),
            },
            engine: WorkloadMeasurements {
                version: "e".into(),
                binary_sha256: "c".repeat(64),
            },
            ope: None,
            attested_mtls: None,
        }
    }

    #[tokio::test]
    async fn nonce_echo_verifier_ok() {
        let nonce = "aabbccddeeff00112233445566778899";
        let resp = AttestedConnectResponse {
            ok: true,
            gateway_attestation: Some(sample_bundle()),
            pool_target_ack: Some(1),
            gateway_challenge_nonce: Some(nonce.into()),
        };
        NonceEchoGatewayAttestationVerifier
            .verify_connect_response(&resp, nonce, &"aa".repeat(32))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn nonce_echo_verifier_missing_attestation() {
        let resp = AttestedConnectResponse {
            ok: true,
            gateway_attestation: None,
            pool_target_ack: None,
            gateway_challenge_nonce: Some("aabbccddeeff00112233445566778899".into()),
        };
        let err = NonceEchoGatewayAttestationVerifier
            .verify_connect_response(&resp, "aabbccddeeff00112233445566778899", &"aa".repeat(32))
            .await
            .unwrap_err();
        assert!(matches!(err, PlaneError::GatewayAttestationMissing));
    }

    #[test]
    fn tls_leaf_bind_accepts_matching_mock_quote() {
        let leaf = "ab".repeat(32);
        let claims = ie_attestation::QuoteClaims {
            v: 1,
            kind: CpuTeeKind::SevSnp,
            ed25519_public: "pub".into(),
            tls_client_cert_sha256: leaf.clone(),
            engine: WorkloadMeasurements {
                version: "gw".into(),
                binary_sha256: "c".repeat(64),
            },
            vllm: WorkloadMeasurements {
                version: "sh".into(),
                binary_sha256: "d".repeat(64),
            },
            ope: None,
            attested_mtls: None,
            launch_digest: None,
            epoch: None,
            issued_at: "2026-08-31T00:00:00Z".into(),
        };
        let bundle = AttestationBundle {
            cpu_tee: CpuTeeAttestation {
                kind: CpuTeeKind::SevSnp,
                quote: ie_attestation::build_mock_cpu_quote(&claims),
                verdict: AttestationVerdict::Pass,
                policy_id: "p".into(),
                endorsement: None,
            },
            gpu_tee: GpuTeeAttestation {
                kind: GpuTeeKind::NvCc,
                evidence: "g".into(),
                verdict: AttestationVerdict::Pass,
            },
            vllm: claims.vllm.clone(),
            engine: claims.engine.clone(),
            ope: None,
            attested_mtls: None,
        };
        assert_gateway_tls_leaf(&bundle, &leaf).unwrap();
        assert!(matches!(
            assert_gateway_tls_leaf(&bundle, &"ff".repeat(32)),
            Err(PlaneError::GatewayTlsCertMismatch)
        ));
    }

    #[test]
    fn tls_leaf_bind_rejects_empty_quote_field() {
        let claims = ie_attestation::QuoteClaims {
            v: 1,
            kind: CpuTeeKind::SevSnp,
            ed25519_public: "pub".into(),
            tls_client_cert_sha256: String::new(),
            engine: WorkloadMeasurements {
                version: "gw".into(),
                binary_sha256: "c".repeat(64),
            },
            vllm: WorkloadMeasurements {
                version: "sh".into(),
                binary_sha256: "d".repeat(64),
            },
            ope: None,
            attested_mtls: None,
            launch_digest: None,
            epoch: None,
            issued_at: "2026-08-31T00:00:00Z".into(),
        };
        let bundle = AttestationBundle {
            cpu_tee: CpuTeeAttestation {
                kind: CpuTeeKind::SevSnp,
                quote: ie_attestation::build_mock_cpu_quote(&claims),
                verdict: AttestationVerdict::Pass,
                policy_id: "p".into(),
                endorsement: None,
            },
            gpu_tee: GpuTeeAttestation {
                kind: GpuTeeKind::NvCc,
                evidence: "g".into(),
                verdict: AttestationVerdict::Pass,
            },
            vllm: claims.vllm,
            engine: claims.engine,
            ope: None,
            attested_mtls: None,
        };
        assert!(matches!(
            assert_gateway_tls_leaf(&bundle, &"aa".repeat(32)),
            Err(PlaneError::GatewayTlsCertUnbound)
        ));
    }
}
