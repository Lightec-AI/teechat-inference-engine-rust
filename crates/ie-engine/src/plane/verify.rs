use async_trait::async_trait;
use ie_protocol::AttestedConnectResponse;

use super::error::PlaneError;

/// Optional SEC-029 gateway platform attestation verify (full quote parse deferred).
#[async_trait]
pub trait GatewayAttestationVerifier: Send + Sync {
    async fn verify_connect_response(
        &self,
        response: &AttestedConnectResponse,
        expected_nonce: &str,
    ) -> Result<(), PlaneError>;
}

/// No-op verifier for dials that skip platform attestation cross-check.
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

/// Fail-closed verifier that requires attestation + matching challenge nonce echo.
pub struct NonceEchoGatewayAttestationVerifier;

#[async_trait]
impl GatewayAttestationVerifier for NonceEchoGatewayAttestationVerifier {
    async fn verify_connect_response(
        &self,
        response: &AttestedConnectResponse,
        expected_nonce: &str,
    ) -> Result<(), PlaneError> {
        if response.gateway_attestation.is_none() {
            return Err(PlaneError::GatewayAttestationMissing);
        }
        let Some(echo) = response.gateway_challenge_nonce.as_deref() else {
            return Err(PlaneError::GatewayChallengeNonceNotBound);
        };
        let Some(norm) = super::challenge::normalize_gateway_connect_challenge_nonce(echo) else {
            return Err(PlaneError::GatewayChallengeNonceMismatch);
        };
        if norm != expected_nonce {
            return Err(PlaneError::GatewayChallengeNonceMismatch);
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
