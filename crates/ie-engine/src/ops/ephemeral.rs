//! Ephemeral identity helpers (port of `ephemeral.ts`).

use ie_protocol::EngineHybridPublic;

pub fn ephemeral_signing_bytes(
    engine_id: &str,
    epoch_id: &str,
    not_after: &str,
    hybrid: &EngineHybridPublic,
) -> Vec<u8> {
    [
        "OPE-ENGINE-EPHEMERAL-v1",
        engine_id,
        epoch_id,
        not_after,
        hybrid.mlkem_encapsulation_key.as_str(),
        hybrid.x25519_public.as_str(),
    ]
    .join("\0")
    .into_bytes()
}

pub fn parse_iso_time_ms(s: &str) -> Option<u64> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.timestamp_millis() as u64)
}

pub fn is_epoch_active(not_before: &str, not_after: &str, now_ms: u64, skew_ms: u64) -> bool {
    let start = parse_iso_time_ms(not_before).unwrap_or(0);
    let end = parse_iso_time_ms(not_after).unwrap_or(0);
    let grace = skew_ms;
    now_ms >= start.saturating_sub(grace) && now_ms <= end.saturating_add(grace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ie_protocol::EngineHybridPublic;

    #[test]
    fn ephemeral_signing_bytes_stable() {
        let hybrid = EngineHybridPublic {
            kex: "x25519-mlkem768".into(),
            mlkem_encapsulation_key: "mlk".into(),
            x25519_public: "x".into(),
        };
        let bytes = ephemeral_signing_bytes("eng", "epoch-1", "2026-01-01T00:00:00Z", &hybrid);
        assert!(bytes.starts_with(b"OPE-ENGINE-EPHEMERAL-v1"));
    }
}
