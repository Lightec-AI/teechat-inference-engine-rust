//! Convert between `ie_protocol::OpeEnvelope` and `ope_envelope::Envelope`.

use ie_protocol::OpeEnvelope;
use ope_envelope::Envelope;
use serde_json::Value;

use crate::CryptoError;

pub fn protocol_to_ope_envelope(env: &OpeEnvelope) -> Result<Envelope, CryptoError> {
    let value = serde_json::to_value(env)?;
    Ok(serde_json::from_value(value)?)
}

pub fn ope_to_protocol_envelope(env: &Envelope) -> Result<OpeEnvelope, CryptoError> {
    let value = serde_json::to_value(env)?;
    Ok(serde_json::from_value(value)?)
}

pub fn envelope_from_json(value: &Value) -> Result<Envelope, CryptoError> {
    Ok(serde_json::from_value(value.clone())?)
}

pub fn envelope_to_json(env: &Envelope) -> Result<Value, CryptoError> {
    Ok(serde_json::to_value(env)?)
}
