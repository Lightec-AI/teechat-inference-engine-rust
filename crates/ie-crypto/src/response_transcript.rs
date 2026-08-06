//! RB-06 response transcript helpers (library wiring; off the wire by default).
//!
//! Enable with `TEECHAT_OPE_RESPONSE_TRANSCRIPT=1` only after clients consume
//! [`TranscriptWriter`] frames. Until then this module is for unit tests and
//! staged cutover — do not flip the env on production engines.

use std::collections::HashMap;

use ope_crypto::SecretKey;
use ope_envelope::{
    SignedTranscriptHeader, TranscriptFrame, TranscriptHeader, TranscriptWriter, TRANSCRIPT_VERSION,
};

/// Whether the engine should emit RB-06 transcript frames on the response stream.
pub fn response_transcript_enabled(env: &HashMap<String, String>) -> bool {
    matches!(
        env.get("TEECHAT_OPE_RESPONSE_TRANSCRIPT")
            .map(|s| s.trim())
            .unwrap_or(""),
        "1" | "true" | "on" | "required"
    )
}

/// Holds a [`TranscriptWriter`] for one response.
pub struct ResponseTranscriptSession {
    writer: TranscriptWriter,
}

impl ResponseTranscriptSession {
    pub fn begin(
        signing_key: &SecretKey,
        request_nonce: impl Into<String>,
        engine_id: impl Into<String>,
        epoch_id: impl Into<String>,
        content_alg: impl Into<String>,
    ) -> Result<(SignedTranscriptHeader, Self), ope_envelope::TranscriptError> {
        let header = TranscriptHeader {
            ope_transcript: TRANSCRIPT_VERSION.into(),
            request_nonce: request_nonce.into(),
            engine_id: engine_id.into(),
            epoch_id: epoch_id.into(),
            content_alg: content_alg.into(),
        };
        let (signed, writer) = TranscriptWriter::begin(header, signing_key)?;
        Ok((signed, Self { writer }))
    }

    pub fn push(
        &mut self,
        sealed_frame: &[u8],
        final_frame: bool,
    ) -> Result<TranscriptFrame, ope_envelope::TranscriptError> {
        self.writer.push(sealed_frame, final_frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ope_crypto::mock_keypair_from_seed;
    use ope_envelope::{TranscriptExpectations, TranscriptReader};

    #[test]
    fn header_then_frames_round_trip() {
        let kp = mock_keypair_from_seed(&[9u8; 32]);
        let (signed, mut session) = ResponseTranscriptSession::begin(
            &kp.secret,
            "req-nonce",
            "engine-1",
            "epoch-a",
            "chacha20poly1305",
        )
        .unwrap();
        let expectations = TranscriptExpectations {
            request_nonce: Some("req-nonce".into()),
            engine_id: Some("engine-1".into()),
            epoch_id: Some("epoch-a".into()),
        };
        let mut reader = TranscriptReader::begin(&signed, &kp.public, &expectations).unwrap();
        let f0 = session.push(b"cipher-0", false).unwrap();
        reader.accept(&f0).unwrap();
        let f1 = session.push(b"cipher-1", true).unwrap();
        reader.accept(&f1).unwrap();
        reader.finish().unwrap();
    }

    #[test]
    fn flag_off_by_default() {
        let env = HashMap::new();
        assert!(!response_transcript_enabled(&env));
        let mut off = HashMap::new();
        off.insert("TEECHAT_OPE_RESPONSE_TRANSCRIPT".into(), "off".into());
        assert!(!response_transcript_enabled(&off));
        let mut on = HashMap::new();
        on.insert("TEECHAT_OPE_RESPONSE_TRANSCRIPT".into(), "1".into());
        assert!(response_transcript_enabled(&on));
    }
}
