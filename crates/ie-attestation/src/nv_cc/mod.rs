mod collect;
mod mock;
mod policy;
mod verify;

pub use collect::{
    collect_nv_cc_gpu_evidence_b64, nvattest_bin_from_env, resolve_nvattest_bin,
};
pub use mock::{build_gpu_not_applicable_evidence, encode_legacy_mock_gpu_evidence, verify_mock_nv_cc_gpu_evidence};
pub use policy::{default_gpu_attestation_policy, GpuAttestationPolicy, GpuEvidenceVerifyResult};
pub use verify::{validate_nv_gpu_claims_against_policy, verify_nv_cc_gpu_evidence};
