//! Receiver-side check that a quote is evidence for the epoch in front of us.
//!
//! Verifying the quote proves the claims came out of a measured TEE. This
//! module is the second half: that the epoch keys those claims describe are the
//! same keys the registration asks us to encrypt to. Without it a valid quote
//! for epoch A would authorize epoch B's keys, which is the hole the long-lived
//! identity signature used to paper over (RB-45, RB-52).
//!
//! Pure comparison, no crypto. Kept byte-for-byte in step with
//! `TeaChat/vendor/inference-engine/src/epoch-evidence.ts`.

use ie_protocol::EngineHybridPublic;

use crate::claims::{QuoteClaims, QuoteEpochClaims};

/// The epoch a caller is being asked to accept.
pub struct EpochEvidenceSubject<'a> {
    pub engine_id: &'a str,
    pub epoch_id: &'a str,
    pub not_before: &'a str,
    pub not_after: &'a str,
    pub hybrid: &'a EngineHybridPublic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochEvidenceError {
    /// Connect-scoped evidence: the engine predates bind v2. Distinct from a
    /// mismatch so callers can keep a compatibility path without also
    /// accepting evidence that describes something else.
    Absent,
    EngineMismatch,
    EpochMismatch,
    WindowMismatch,
    MlkemMismatch,
    X25519Mismatch,
    UsageKeyMissing,
}

impl EpochEvidenceError {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "epoch_evidence_absent",
            Self::EngineMismatch => "epoch_evidence_engine_mismatch",
            Self::EpochMismatch => "epoch_evidence_epoch_mismatch",
            Self::WindowMismatch => "epoch_evidence_window_mismatch",
            Self::MlkemMismatch => "epoch_evidence_mlkem_mismatch",
            Self::X25519Mismatch => "epoch_evidence_x25519_mismatch",
            Self::UsageKeyMissing => "epoch_evidence_usage_key_missing",
        }
    }
}

impl std::fmt::Display for EpochEvidenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Base64url material must match exactly; a case-folded compare would be wrong.
fn same_key(a: &str, b: &str) -> bool {
    !a.is_empty() && a == b
}

/// Match a quote's epoch block against the epoch being registered.
pub fn match_epoch_evidence<'a>(
    claims: &'a QuoteClaims,
    subject: &EpochEvidenceSubject<'_>,
) -> Result<&'a QuoteEpochClaims, EpochEvidenceError> {
    let epoch = claims.epoch.as_ref().ok_or(EpochEvidenceError::Absent)?;

    if epoch.engine_id != subject.engine_id {
        return Err(EpochEvidenceError::EngineMismatch);
    }
    if epoch.epoch_id != subject.epoch_id {
        return Err(EpochEvidenceError::EpochMismatch);
    }
    if epoch.not_before != subject.not_before || epoch.not_after != subject.not_after {
        return Err(EpochEvidenceError::WindowMismatch);
    }
    if !same_key(
        &epoch.mlkem_encapsulation_key,
        &subject.hybrid.mlkem_encapsulation_key,
    ) {
        return Err(EpochEvidenceError::MlkemMismatch);
    }
    if !same_key(&epoch.x25519_public, &subject.hybrid.x25519_public) {
        return Err(EpochEvidenceError::X25519Mismatch);
    }
    if epoch.usage_signing_public.trim().is_empty() {
        return Err(EpochEvidenceError::UsageKeyMissing);
    }
    Ok(epoch)
}

/// Whether a quote carries per-epoch evidence at all.
pub fn has_epoch_evidence(claims: &QuoteClaims) -> bool {
    claims.epoch.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ie_protocol::{CpuTeeKind, WorkloadMeasurements};

    fn hybrid() -> EngineHybridPublic {
        EngineHybridPublic {
            kex: "X25519MLKEM768".into(),
            mlkem_encapsulation_key: "bWxrZW0".into(),
            x25519_public: "eDI1NTE5".into(),
        }
    }

    fn epoch_claims() -> QuoteEpochClaims {
        QuoteEpochClaims {
            engine_id: "engine-1".into(),
            epoch_id: "epoch-1".into(),
            not_before: "2026-07-31T00:00:00.000Z".into(),
            not_after: "2026-08-30T00:00:00.000Z".into(),
            mlkem_encapsulation_key: "bWxrZW0".into(),
            x25519_public: "eDI1NTE5".into(),
            usage_signing_public: "dXNhZ2U".into(),
        }
    }

    fn claims_with(epoch: Option<QuoteEpochClaims>) -> QuoteClaims {
        QuoteClaims {
            v: 1,
            kind: CpuTeeKind::SevSnp,
            ed25519_public: "aWQ".into(),
            tls_client_cert_sha256: "aa".repeat(32),
            engine: WorkloadMeasurements {
                version: "0.12.1".into(),
                binary_sha256: "a".repeat(64),
            },
            vllm: WorkloadMeasurements {
                version: "v1".into(),
                binary_sha256: "b".repeat(64),
            },
            ope: None,
            attested_mtls: None,
            launch_digest: None,
            epoch,
            issued_at: "2026-07-31T00:00:00.000Z".into(),
        }
    }

    fn subject<'a>(e: &'a QuoteEpochClaims, h: &'a EngineHybridPublic) -> EpochEvidenceSubject<'a> {
        EpochEvidenceSubject {
            engine_id: &e.engine_id,
            epoch_id: &e.epoch_id,
            not_before: &e.not_before,
            not_after: &e.not_after,
            hybrid: h,
        }
    }

    #[test]
    fn accepts_evidence_for_the_epoch_presented() {
        let e = epoch_claims();
        let h = hybrid();
        let claims = claims_with(Some(e.clone()));
        assert!(match_epoch_evidence(&claims, &subject(&e, &h)).is_ok());
    }

    #[test]
    fn reports_absence_separately_from_mismatch() {
        let e = epoch_claims();
        let h = hybrid();
        let claims = claims_with(None);
        assert_eq!(
            match_epoch_evidence(&claims, &subject(&e, &h)).unwrap_err(),
            EpochEvidenceError::Absent
        );
        assert!(!has_epoch_evidence(&claims));
    }

    #[test]
    fn rejects_each_field_that_does_not_describe_the_subject() {
        let h = hybrid();
        let base = epoch_claims();

        let cases: Vec<(QuoteEpochClaims, EpochEvidenceError)> = vec![
            (
                QuoteEpochClaims {
                    engine_id: "other".into(),
                    ..base.clone()
                },
                EpochEvidenceError::EngineMismatch,
            ),
            (
                QuoteEpochClaims {
                    epoch_id: "other".into(),
                    ..base.clone()
                },
                EpochEvidenceError::EpochMismatch,
            ),
            (
                QuoteEpochClaims {
                    not_after: "2030-01-01T00:00:00.000Z".into(),
                    ..base.clone()
                },
                EpochEvidenceError::WindowMismatch,
            ),
            (
                QuoteEpochClaims {
                    mlkem_encapsulation_key: "other".into(),
                    ..base.clone()
                },
                EpochEvidenceError::MlkemMismatch,
            ),
            (
                QuoteEpochClaims {
                    x25519_public: "other".into(),
                    ..base.clone()
                },
                EpochEvidenceError::X25519Mismatch,
            ),
            (
                QuoteEpochClaims {
                    usage_signing_public: "  ".into(),
                    ..base.clone()
                },
                EpochEvidenceError::UsageKeyMissing,
            ),
        ];

        for (attested, want) in cases {
            // The subject stays the honest epoch; the quote attests something else.
            let claims = claims_with(Some(attested));
            let got = match_epoch_evidence(&claims, &subject(&base, &h)).unwrap_err();
            assert_eq!(got, want, "expected {want} for mutated evidence");
        }
    }

    #[test]
    fn two_empty_keys_are_not_a_match() {
        let mut e = epoch_claims();
        e.x25519_public = String::new();
        let h = EngineHybridPublic {
            x25519_public: String::new(),
            ..hybrid()
        };
        let claims = claims_with(Some(e.clone()));
        assert_eq!(
            match_epoch_evidence(&claims, &subject(&e, &h)).unwrap_err(),
            EpochEvidenceError::X25519Mismatch
        );
    }
}
