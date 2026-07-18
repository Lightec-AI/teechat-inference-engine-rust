//! Gateway ↔ engine OPE inference protocol types.
//!
//! Port of `@teechat/inference-engine` `src/protocol/types.ts`.

mod traffic;

pub use traffic::*;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineStartupIdentity {
    pub engine_id: String,
    pub kex: String,
    pub ed25519_public: String,
}

/// Deprecated startup identity + ephemeral hybrid; not a single static ML-KEM key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineIdentity {
    pub engine_id: String,
    pub kex: String,
    pub ed25519_public: String,
    pub mlkem_encapsulation_key: String,
    pub x25519_public: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineHybridPublic {
    pub kex: String,
    pub mlkem_encapsulation_key: String,
    pub x25519_public: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadMeasurements {
    pub version: String,
    pub binary_sha256: String,
}

/// Optional OPE identity (independent TCB; not equal to `engine.binary_sha256`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpeWorkloadIdentity {
    pub version: String,
    pub git_sha: String,
    pub libope_ffi_sha256: String,
}

/// Optional attested-mtls identity (independent TCB).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestedMtlsWorkloadIdentity {
    pub version: String,
    pub git_sha: String,
    pub lib_attested_mtls_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CpuTeeKind {
    Tdx,
    #[serde(rename = "sev-snp")]
    SevSnp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttestationVerdict {
    Pass,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpuTeeAttestation {
    pub kind: CpuTeeKind,
    pub quote: String,
    pub verdict: AttestationVerdict,
    pub policy_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GpuTeeKind {
    #[serde(rename = "nv-cc")]
    NvCc,
    #[serde(rename = "amd-gpu-tee")]
    AmdGpuTee,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuTeeAttestation {
    pub kind: GpuTeeKind,
    pub evidence: String,
    pub verdict: AttestationVerdict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationBundle {
    pub cpu_tee: CpuTeeAttestation,
    pub gpu_tee: GpuTeeAttestation,
    pub vllm: WorkloadMeasurements,
    /// InferenceEngine runtime measurement (compiled/bundled IE artifact).
    pub engine: WorkloadMeasurements,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ope: Option<OpeWorkloadIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attested_mtls: Option<AttestedMtlsWorkloadIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineEphemeralRegisterRequest {
    pub engine_id: String,
    pub epoch_id: String,
    pub not_before: String,
    pub not_after: String,
    pub hybrid: EngineHybridPublic,
    pub identity_signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<AttestationBundle>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineTrustIdentity {
    pub ed25519_public: String,
    pub identity_signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineTrustBundle {
    pub engine_id: String,
    pub epoch_id: String,
    pub not_before: String,
    pub not_after: String,
    pub hybrid: EngineHybridPublic,
    pub identity: EngineTrustIdentity,
    pub attestation: AttestationBundle,
    pub gateway_cached_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpeE2eDescriptor {
    pub kex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_share: Option<String>,
    pub engine_mlkem_encap: String,
    pub engine_x25519: String,
    pub ephemeral_epoch: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_alg: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageReport {
    pub request_id: String,
    pub conversation_id: String,
    pub engine_id: String,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub ts: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedUsageReport {
    pub report: UsageReport,
    pub sig: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GatewayPlaneTaskPayload {
    pub messages: Vec<GatewayPlaneMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayPlaneMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpeEnvelopeMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metering: Option<OpeEnvelopeMetering>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<OpeEnvelopeRoute>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traffic_class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_task: Option<GatewayPlaneTaskPayload>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpeEnvelopeMetering {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub units: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpeEnvelopeRoute {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpeEnvelope {
    pub ope_version: String,
    pub alg: String,
    pub enc: String,
    pub kid: String,
    pub recipient: String,
    pub ts: String,
    pub nonce: String,
    pub payload_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<OpeEnvelopeMeta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ciphertext: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e2e: Option<OpeE2eDescriptor>,
}

pub const HEADER_ENGINE_CLIENT_CERT: &str = "x-ope-engine-client-cert-sha256";
pub const HEADER_USAGE_REPORT: &str = "x-ope-usage-report";
pub const HEADER_OPE_GATEWAY_ID: &str = "x-ope-gateway-id";
pub const HEADER_OPE_EPHEMERAL_EPOCH: &str = "x-ope-ephemeral-epoch";
pub const HEADER_OPE_CONVERSATION_ID: &str = "x-ope-conversation-id";
pub const HEADER_OPE_REQUEST_ID: &str = "x-ope-request-id";
pub const HEADER_OPE_SESSION_ID: &str = "x-ope-session-id";
pub const HEADER_OPE_TRAFFIC_CLASS: &str = "x-ope-traffic-class";
pub const CONTENT_TYPE_OPE_JSON: &str = "application/ope+json";
pub const INFERENCE_PATH: &str = "/v1/ope/inference";

pub const ENGINE_PLANE_PATH_CONNECT: &str = "/v1/ope/control/connect";
pub const ENGINE_PLANE_PATH_DISCONNECT: &str = "/v1/ope/control/disconnect";
pub const ENGINE_PLANE_PATH_EPHEMERAL: &str = "/v1/ope/control/ephemeral";
pub const ENGINE_PLANE_PATH_POOL: &str = "/v1/ope/control/pool";
pub const ENGINE_PLANE_PATH_WORK_PULL: &str = "/v1/ope/work/pull";

pub const MOCK_MLKEM_ENCAP_B64URL_LEN: usize = 1184;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestedConnectRequest {
    pub session_id: String,
    pub engine_id: String,
    pub models: Vec<String>,
    pub identity: EngineStartupIdentity,
    pub attestation: AttestationBundle,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pool_target_size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_challenge_nonce: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestedConnectResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_attestation: Option<AttestationBundle>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pool_target_ack: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_challenge_nonce: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestedPoolResizeRequest {
    pub pool_target_size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttestedDisconnectReason {
    Shutdown,
    Upgrade,
    Admin,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestedDisconnectRequest {
    pub engine_id: String,
    pub session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<AttestedDisconnectReason>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestedDisconnectResponse {
    pub ok: bool,
    pub draining: bool,
    pub in_flight: u32,
    pub ready_to_close: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_deregistered: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attestation_bundle_roundtrip() {
        let bundle = AttestationBundle {
            cpu_tee: CpuTeeAttestation {
                kind: CpuTeeKind::SevSnp,
                quote: "quote".into(),
                verdict: AttestationVerdict::Pass,
                policy_id: "teechat-cpu-tee-prod-v1".into(),
            },
            gpu_tee: GpuTeeAttestation {
                kind: GpuTeeKind::NvCc,
                evidence: "gpu".into(),
                verdict: AttestationVerdict::Pass,
            },
            vllm: WorkloadMeasurements {
                version: "upstream".into(),
                binary_sha256: "abc".into(),
            },
            engine: WorkloadMeasurements {
                version: "0.1.0".into(),
                binary_sha256: "def".into(),
            },
            ope: Some(OpeWorkloadIdentity {
                version: "0.1.0".into(),
                git_sha: "ffbee812".into(),
                libope_ffi_sha256: "0803b3cb".into(),
            }),
            attested_mtls: None,
        };
        let json = serde_json::to_string(&bundle).unwrap();
        let parsed: AttestationBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, bundle);
    }
}
