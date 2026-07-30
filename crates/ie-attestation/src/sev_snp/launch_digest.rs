//! Challenge-canonical launch digest from SNP AttestationReport MEASUREMENT.
//!
//! Encoding matches OpenAPI / app-verity bake:
//! `sha256(ascii_hex(raw_MEASUREMENT))` where MEASUREMENT is 48 bytes (96 hex).
//!
//! Field offset: AMD SEV-SNP Firmware ABI — MEASUREMENT at 0x90, length 48.
//! REPORT_DATA is at 0x50 (see verify_report.rs).

use sha2::{Digest, Sha256};

const MEASUREMENT_OFFSET: usize = 0x90;
const MEASUREMENT_LEN: usize = 48;

/// Raw 48-byte MEASUREMENT from a SNP attestation report, if present.
pub fn extract_measurement_from_report(report: &[u8]) -> Option<[u8; MEASUREMENT_LEN]> {
    if report.len() < MEASUREMENT_OFFSET + MEASUREMENT_LEN {
        return None;
    }
    let mut out = [0u8; MEASUREMENT_LEN];
    out.copy_from_slice(&report[MEASUREMENT_OFFSET..MEASUREMENT_OFFSET + MEASUREMENT_LEN]);
    Some(out)
}

/// Challenge-canonical composed LD: sha256 over lowercase ASCII hex of raw MEASUREMENT.
pub fn challenge_canonical_launch_digest(raw_measurement_hex: &str) -> String {
    let normalized = raw_measurement_hex.trim().to_ascii_lowercase();
    hex::encode(Sha256::digest(normalized.as_bytes()))
}

/// Extract challenge-canonical launch_digest from a binary SNP report.
pub fn launch_digest_from_report(report: &[u8]) -> Option<String> {
    let m = extract_measurement_from_report(report)?;
    let raw_hex = hex::encode(m);
    Some(challenge_canonical_launch_digest(&raw_hex))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_canonical_is_64_hex() {
        let raw = "ab".repeat(48);
        let ld = challenge_canonical_launch_digest(&raw);
        assert_eq!(ld.len(), 64);
        assert!(ld.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn extract_measurement_offset() {
        let mut report = vec![0u8; MEASUREMENT_OFFSET + MEASUREMENT_LEN];
        for (i, b) in report[MEASUREMENT_OFFSET..].iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(1);
        }
        let m = extract_measurement_from_report(&report).expect("m");
        assert_eq!(m[0], 1);
        assert_eq!(m[47], 48);
        let ld = launch_digest_from_report(&report).expect("ld");
        assert_eq!(ld.len(), 64);
    }
}
