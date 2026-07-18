//! Gateway connect challenge nonce helpers (port of `engine/gateway-connect-nonce.ts`).

use rand::RngCore;

/// Generate a 32-char lowercase hex nonce (16 random bytes).
pub fn generate_gateway_connect_challenge_nonce() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Trim + lowercase; accept only exactly 32 hex chars.
pub fn normalize_gateway_connect_challenge_nonce(value: &str) -> Option<String> {
    let trimmed = value.trim().to_ascii_lowercase();
    if trimmed.len() != 32 {
        return None;
    }
    if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(trimmed)
}

pub fn is_valid_gateway_connect_challenge_nonce(value: &str) -> bool {
    normalize_gateway_connect_challenge_nonce(value).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_is_32_hex() {
        let n = generate_gateway_connect_challenge_nonce();
        assert_eq!(n.len(), 32);
        assert!(is_valid_gateway_connect_challenge_nonce(&n));
    }

    #[test]
    fn normalize_trims_and_lowercases() {
        assert_eq!(
            normalize_gateway_connect_challenge_nonce("  AABBCCDDEEFF00112233445566778899  "),
            Some("aabbccddeeff00112233445566778899".into())
        );
    }

    #[test]
    fn normalize_rejects_bad_length_and_charset() {
        assert!(normalize_gateway_connect_challenge_nonce("abc").is_none());
        assert!(normalize_gateway_connect_challenge_nonce(&"g".repeat(32)).is_none());
    }
}
