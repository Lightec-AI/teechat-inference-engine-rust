//! Usage report signing (port of `metering.ts`).

use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use ie_protocol::{SignedUsageReport, UsageReport};
use ope_crypto::decode;
use serde_json::json;

pub fn usage_report_signing_bytes(report: &UsageReport) -> Vec<u8> {
    let canonical = json!({
        "completion_tokens": report.completion_tokens,
        "conversation_id": report.conversation_id,
        "engine_id": report.engine_id,
        "prompt_tokens": report.prompt_tokens,
        "request_id": report.request_id,
        "ts": report.ts,
    });
    serde_json::to_vec(&canonical).unwrap_or_default()
}

pub fn sign_usage_report(signing_key: &ed25519_dalek::SigningKey, report: &UsageReport) -> String {
    let sig = signing_key.sign(&usage_report_signing_bytes(report));
    ope_crypto::encode(sig.to_bytes().as_slice())
}

pub fn verify_usage_report(ed25519_public_b64: &str, signed: &SignedUsageReport) -> bool {
    let msg = usage_report_signing_bytes(&signed.report);
    let sig_bytes = decode(&signed.sig).ok();
    let pub_bytes = decode(ed25519_public_b64).ok();
    let (Some(sig_bytes), Some(pub_bytes)) = (sig_bytes, pub_bytes) else {
        return false;
    };
    let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.as_slice().try_into() else {
        return false;
    };
    let Ok(pub_arr): Result<[u8; 32], _> = pub_bytes.as_slice().try_into() else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&pub_arr) else {
        return false;
    };
    key.verify(&msg, &Signature::from_bytes(&sig_arr)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ope_crypto::{mock_keypair_from_seed, DEV_VECTOR_001_SEED};

    #[test]
    fn sign_and_verify_usage_report() {
        let kp = mock_keypair_from_seed(&DEV_VECTOR_001_SEED);
        let pub_b64 = ope_crypto::encode(kp.public.to_bytes().as_slice());
        let report = UsageReport {
            request_id: "r".into(),
            conversation_id: "c".into(),
            engine_id: "e".into(),
            prompt_tokens: 1,
            completion_tokens: 2,
            ts: "2026-01-01T00:00:00Z".into(),
        };
        let sig = sign_usage_report(&kp.secret, &report);
        let signed = SignedUsageReport { report, sig };
        assert!(verify_usage_report(&pub_b64, &signed));
    }
}
