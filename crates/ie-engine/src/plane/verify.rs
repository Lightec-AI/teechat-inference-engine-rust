use async_trait::async_trait;
use ie_attestation::{
    verify_platform_attestation_bundle_mock, AttestationPolicy, PlatformAttestationBind,
    PlatformAttestationPolicy,
};
use ie_protocol::AttestedConnectResponse;

use super::error::PlaneError;

/// Optional SEC-029 gateway platform attestation verify.
#[async_trait]
pub trait GatewayAttestationVerifier: Send + Sync {
    async fn verify_connect_response(
        &self,
        response: &AttestedConnectResponse,
        expected_nonce: &str,
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
    ) -> Result<(), PlaneError> {
        // Nonce + SNP report_data first (same as NonceEcho).
        NonceEchoGatewayAttestationVerifier
            .verify_connect_response(response, expected_nonce)
            .await?;

        let bundle = response
            .gateway_attestation
            .as_ref()
            .expect("nonce echo verified attestation present");

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let verdict = verify_platform_attestation_bundle_mock(
            bundle,
            &self.engine_policy,
            &self.platform_policy,
            &self.bind,
            now_ms,
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
            .verify_connect_response(&resp, nonce)
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
            .verify_connect_response(&resp, "aabbccddeeff00112233445566778899")
            .await
            .unwrap_err();
        assert!(matches!(err, PlaneError::GatewayAttestationMissing));
    }
}
