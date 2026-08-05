use serde::{Deserialize, Serialize};

use ie_protocol::{
    AttestationBundle, AttestationVerdict, AttestedMtlsWorkloadIdentity, CpuTeeAttestation,
    CpuTeeKind, GpuTeeAttestation, GpuTeeKind, OpeWorkloadIdentity, WorkloadMeasurements,
};

/// The epoch key material an attestation report vouches for (bind v2).
///
/// Connect-scoped evidence only covers the boot identity, which leaves every
/// epoch minted afterwards resting on a software signature by that identity.
/// Naming the epoch's own keys inside the report is what removes that gap
/// (RB-45); the receiver-side match lives in `epoch_evidence`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteEpochClaims {
    pub engine_id: String,
    pub epoch_id: String,
    pub not_before: String,
    pub not_after: String,
    pub mlkem_encapsulation_key: String,
    pub x25519_public: String,
    pub usage_signing_public: String,
}

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
    /// Challenge-canonical composed SNP launch digest (Wave B).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub launch_digest: Option<String>,
    /// Present on per-epoch (bind v2) evidence; absent on connect-scoped evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<QuoteEpochClaims>,
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
            launch_digest: None,
            epoch: None,
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
                endorsement: None,
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
