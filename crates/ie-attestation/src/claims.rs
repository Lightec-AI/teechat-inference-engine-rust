use serde::{Deserialize, Serialize};

use ie_protocol::{
    AttestationBundle, AttestationVerdict, AttestedMtlsWorkloadIdentity, CpuTeeAttestation,
    CpuTeeKind, GpuTeeAttestation, GpuTeeKind, OpeWorkloadIdentity, WorkloadMeasurements,
};

/// Normalized claims extracted from a CPU TEE quote (port of `attestation.ts` `QuoteClaims`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteClaims {
    pub v: u8,
    pub kind: CpuTeeKind,
    pub ed25519_public: String,
    pub tls_client_cert_sha256: String,
    pub engine: WorkloadMeasurements,
    pub vllm: WorkloadMeasurements,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ope: Option<OpeWorkloadIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attested_mtls: Option<AttestedMtlsWorkloadIdentity>,
    pub issued_at: String,
}

impl QuoteClaims {
    pub fn from_measurements(
        ed25519_public: &str,
        tls_client_cert_sha256: &str,
        measurements: &super::measurements::BinaryMeasurements,
        issued_at: &str,
    ) -> Self {
        let mut claims = Self {
            v: 1,
            kind: CpuTeeKind::SevSnp,
            ed25519_public: ed25519_public.to_string(),
            tls_client_cert_sha256: tls_client_cert_sha256.to_ascii_lowercase(),
            engine: WorkloadMeasurements {
                version: measurements.engine_version.clone(),
                binary_sha256: measurements.engine_binary_sha256.clone(),
            },
            vllm: WorkloadMeasurements {
                version: measurements.vllm_version.clone(),
                binary_sha256: measurements.vllm_binary_sha256.clone(),
            },
            ope: None,
            attested_mtls: None,
            issued_at: issued_at.to_string(),
        };
        if let Some(ope) = &measurements.ope {
            claims.ope = Some(OpeWorkloadIdentity {
                version: ope.version.clone(),
                git_sha: ope.git_sha.clone(),
                libope_ffi_sha256: ope.libope_ffi_sha256.clone(),
            });
        }
        if let Some(amt) = &measurements.attested_mtls {
            claims.attested_mtls = Some(AttestedMtlsWorkloadIdentity {
                version: amt.version.clone(),
                git_sha: amt.git_sha.clone(),
                lib_attested_mtls_sha256: amt.lib_attested_mtls_sha256.clone(),
            });
        }
        claims
    }

    pub fn into_attestation_bundle(
        self,
        cpu_quote: String,
        gpu_evidence: String,
        policy_id: &str,
    ) -> AttestationBundle {
        AttestationBundle {
            cpu_tee: CpuTeeAttestation {
                kind: self.kind,
                quote: cpu_quote,
                verdict: AttestationVerdict::Pass,
                policy_id: policy_id.to_string(),
            },
            gpu_tee: GpuTeeAttestation {
                kind: GpuTeeKind::NvCc,
                evidence: gpu_evidence,
                verdict: AttestationVerdict::Pass,
            },
            engine: self.engine,
            vllm: self.vllm,
            ope: self.ope,
            attested_mtls: self.attested_mtls,
        }
    }
}
