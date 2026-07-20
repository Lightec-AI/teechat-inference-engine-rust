//! NV-CC GPU attestation types and policy.

use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct GpuAttestationPolicy {
    pub require_gpu_attestation: bool,
    pub allowed_gpu_driver_versions: HashSet<String>,
    pub allowed_gpu_vbios_versions: HashSet<String>,
    pub allowed_gpu_architectures: HashSet<String>,
    pub max_gpu_evidence_age_ms: u64,
}

impl Default for GpuAttestationPolicy {
    fn default() -> Self {
        Self {
            require_gpu_attestation: true,
            allowed_gpu_driver_versions: HashSet::new(),
            allowed_gpu_vbios_versions: HashSet::new(),
            allowed_gpu_architectures: HashSet::new(),
            max_gpu_evidence_age_ms: 24 * 60 * 60 * 1000,
        }
    }
}

pub fn default_gpu_attestation_policy() -> GpuAttestationPolicy {
    GpuAttestationPolicy::default()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuEvidenceVerifyResult {
    pub ok: bool,
    pub reason: Option<String>,
}
