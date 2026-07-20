//! Legacy mock GPU evidence helpers.

use serde_json::json;

pub fn encode_legacy_mock_gpu_evidence() -> String {
    let payload = json!({
        "v": 1,
        "kind": "nv-cc",
        "source": "mock",
        "collected_at": chrono::Utc::now().to_rfc3339(),
    });
    ope_crypto::encode(payload.to_string().as_bytes())
}

pub fn build_gpu_not_applicable_evidence() -> String {
    let payload = json!({
        "v": 1,
        "kind": "nv-cc",
        "not_applicable": true,
        "collected_at": chrono::Utc::now().to_rfc3339(),
    });
    ope_crypto::encode(payload.to_string().as_bytes())
}

pub fn verify_mock_nv_cc_gpu_evidence(evidence_b64: &str) -> super::policy::GpuEvidenceVerifyResult {
    let Ok(raw) = ope_crypto::decode(evidence_b64) else {
        return fail("decode_failed");
    };
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&raw) else {
        return fail("invalid_json");
    };
    if v.get("source").and_then(|s| s.as_str()) == Some("mock") {
        super::policy::GpuEvidenceVerifyResult {
            ok: true,
            reason: None,
        }
    } else {
        fail("not_mock")
    }
}

fn fail(reason: &str) -> super::policy::GpuEvidenceVerifyResult {
    super::policy::GpuEvidenceVerifyResult {
        ok: false,
        reason: Some(reason.into()),
    }
}
