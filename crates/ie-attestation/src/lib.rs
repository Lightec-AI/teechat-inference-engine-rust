//! SEV-SNP attestation measurements and claim builders.

mod bundle;
mod claims;
mod error;
mod fixture;
mod measurements;
mod mock_quote;
mod nv_cc;
mod platform;
mod policy;
mod refresh;
mod sev_snp;
mod tcb_pins;
mod verify;

pub use bundle::{build_attestation_bundle_from_measurements, BuildAttestationBundleArgs};
pub use claims::QuoteClaims;
pub use error::AttestationError;
pub use fixture::{
    clear_production_quote_backend, create_fixture_production_quote_backend,
    is_production_quote_backend_registered, register_production_quote_backend,
    MockCpuQuoteVerifier, ProductionCpuQuoteVerifier, FIXTURE_INTEL_TDX_QUOTE_PLACEHOLDER,
};
pub use measurements::{
    resolve_binary_measurements_from_env, AttestedMtlsIdentityMeasurements, BinaryMeasurements,
    OpeIdentityMeasurements,
};
pub use mock_quote::{build_mock_cpu_quote, parse_mock_cpu_quote};
pub use nv_cc::{
    build_gpu_not_applicable_evidence, collect_nv_cc_gpu_evidence_b64, default_gpu_attestation_policy,
    encode_legacy_mock_gpu_evidence, nvattest_bin_from_env, resolve_nvattest_bin,
    validate_nv_gpu_claims_against_policy, verify_mock_nv_cc_gpu_evidence, verify_nv_cc_gpu_evidence,
    GpuAttestationPolicy, GpuEvidenceVerifyResult,
};
pub use platform::{
    verify_platform_attestation_bundle, verify_platform_attestation_bundle_mock,
    PlatformAttestationBind, PlatformAttestationPolicy,
};
pub use policy::{
    default_test_attestation_policy, verify_bundle_with_verifier, verify_claims_against_policy,
    AttestationPolicy, AttestationVerifyResult,
};
pub use refresh::{
    create_engine_attestation_refresher, EngineAttestationRefreshContext, EngineAttestationRefresher,
};
pub use sev_snp::{
    bind_report_data_64, build_engine_attestation_bundle, encode_sev_snp_quote_wrapper,
    extract_report_data_from_report, is_sev_snp_guest_device_available, parse_sev_snp_quote_wrapper,
    request_sev_snp_attestation_report, should_use_sev_snp_attestation,
    verify_sev_snp_attestation_report, verify_wrapper_report_data, SevSnpQuoteWrapper,
};
pub use tcb_pins::{load_tcb_pins, validate_tcb_pins, TcbPins, TcbPinsValidation};
pub use verify::{CpuQuoteVerifier, VerifyError};
