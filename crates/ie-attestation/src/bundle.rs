use crate::claims::QuoteClaims;
use crate::measurements::BinaryMeasurements;
use ie_protocol::AttestationBundle;

pub struct BuildAttestationBundleArgs {
    pub ed25519_public: String,
    pub tls_client_cert_sha256: String,
    pub policy_id: Option<String>,
    pub measurements: BinaryMeasurements,
    /// CPU quote wrapper (base64). Production: SEV-SNP guest report from `/dev/sev-guest`.
    pub cpu_quote: String,
    /// GPU evidence (base64). Production: NV-CC attestation blob.
    pub gpu_evidence: String,
    pub issued_at: String,
}

/// Build an `AttestationBundle` from resolved measurements and externally supplied quotes.
///
/// Guest report collection (`requestSevSnpAttestationReport`) and NV-CC collection remain
/// platform-specific and are not implemented in this crate yet.
pub fn build_attestation_bundle_from_measurements(
    args: BuildAttestationBundleArgs,
) -> AttestationBundle {
    let policy_id = args
        .policy_id
        .unwrap_or_else(|| "teechat-cpu-tee-prod-v1".to_string());
    let claims = QuoteClaims::from_measurements(
        &args.ed25519_public,
        &args.tls_client_cert_sha256,
        &args.measurements,
        &args.issued_at,
    );
    claims.into_attestation_bundle(args.cpu_quote, args.gpu_evidence, &policy_id)
}
