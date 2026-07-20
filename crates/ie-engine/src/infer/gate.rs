//! OPE inference envelope gate (port of `server/ope-inference-gate.ts`).

use ie_protocol::{OpeEnvelope, CONTENT_TYPE_OPE_JSON};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpeInferenceGateError {
    ContentTypeMustBeOpeJson,
    E2eEnvelopeRequired,
    E2eEphemeralEpochRequired,
    PlaintextPayloadForbidden,
    CiphertextRequired,
}

impl OpeInferenceGateError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ContentTypeMustBeOpeJson => "content_type_must_be_ope_json",
            Self::E2eEnvelopeRequired => "e2e_envelope_required",
            Self::E2eEphemeralEpochRequired => "e2e_ephemeral_epoch_required",
            Self::PlaintextPayloadForbidden => "plaintext_payload_forbidden",
            Self::CiphertextRequired => "ciphertext_required",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateResult {
    Ok,
    Reject {
        status: u16,
        error: OpeInferenceGateError,
        detail: Option<String>,
    },
}

pub fn validate_ope_inference_content_type(content_type: Option<&str>) -> GateResult {
    let ct = content_type.unwrap_or("");
    if !ct.contains(CONTENT_TYPE_OPE_JSON) {
        return GateResult::Reject {
            status: 415,
            error: OpeInferenceGateError::ContentTypeMustBeOpeJson,
            detail: None,
        };
    }
    GateResult::Ok
}

fn has_forbidden_plaintext(envelope: &OpeEnvelope) -> bool {
    envelope.enc == "none"
}

pub fn validate_ope_inference_envelope(envelope: &OpeEnvelope) -> GateResult {
    if has_forbidden_plaintext(envelope) {
        return GateResult::Reject {
            status: 400,
            error: OpeInferenceGateError::PlaintextPayloadForbidden,
            detail: None,
        };
    }
    if envelope.enc != "e2e-hybrid-pq" || envelope.engine_id.is_none() {
        return GateResult::Reject {
            status: 400,
            error: OpeInferenceGateError::E2eEnvelopeRequired,
            detail: None,
        };
    }
    let ct_ok = envelope
        .ciphertext
        .as_ref()
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    let iv_ok = envelope.iv.as_ref().map(|s| !s.is_empty()).unwrap_or(false);
    if !ct_ok || !iv_ok {
        return GateResult::Reject {
            status: 400,
            error: OpeInferenceGateError::CiphertextRequired,
            detail: None,
        };
    }
    let Some(e2e) = envelope.e2e.as_ref() else {
        return GateResult::Reject {
            status: 400,
            error: OpeInferenceGateError::E2eEphemeralEpochRequired,
            detail: None,
        };
    };
    if e2e.ephemeral_epoch.is_empty()
        || e2e.engine_mlkem_encap.is_empty()
        || e2e.engine_x25519.is_empty()
    {
        return GateResult::Reject {
            status: 400,
            error: OpeInferenceGateError::E2eEphemeralEpochRequired,
            detail: None,
        };
    }
    GateResult::Ok
}

pub fn ope_inference_reject_body(error: &str, detail: Option<&str>) -> String {
    match detail {
        Some(d) => serde_json::json!({ "error": error, "detail": d }).to_string(),
        None => serde_json::json!({ "error": error }).to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ie_protocol::OpeE2eDescriptor;

    fn sample_ok() -> OpeEnvelope {
        OpeEnvelope {
            ope_version: "1.0".into(),
            alg: "EdDSA".into(),
            enc: "e2e-hybrid-pq".into(),
            kid: "k".into(),
            recipient: "g".into(),
            ts: "t".into(),
            nonce: "n".into(),
            payload_hash: "h".into(),
            engine_id: Some("engine".into()),
            meta: None,
            sig: None,
            ciphertext: Some("ct".into()),
            iv: Some("iv".into()),
            e2e: Some(OpeE2eDescriptor {
                kex: "X25519MLKEM768".into(),
                client_share: Some("cs".into()),
                engine_mlkem_encap: "em".into(),
                engine_x25519: "ex".into(),
                ephemeral_epoch: "epoch-1".into(),
                content_alg: None,
                mlkem_ciphertext: None,
                client_x25519: None,
                server_share: None,
            }),
        }
    }

    #[test]
    fn accepts_valid_e2e_envelope() {
        assert_eq!(validate_ope_inference_envelope(&sample_ok()), GateResult::Ok);
    }

    #[test]
    fn rejects_plaintext_enc_none() {
        let mut e = sample_ok();
        e.enc = "none".into();
        assert!(matches!(
            validate_ope_inference_envelope(&e),
            GateResult::Reject {
                error: OpeInferenceGateError::PlaintextPayloadForbidden,
                ..
            }
        ));
    }

    #[test]
    fn rejects_missing_epoch() {
        let mut e = sample_ok();
        if let Some(ref mut e2e) = e.e2e {
            e2e.ephemeral_epoch.clear();
        }
        assert!(matches!(
            validate_ope_inference_envelope(&e),
            GateResult::Reject {
                error: OpeInferenceGateError::E2eEphemeralEpochRequired,
                ..
            }
        ));
    }
}
