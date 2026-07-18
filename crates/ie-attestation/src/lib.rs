//! SEV-SNP attestation measurements and claim builders.
//!
//! Port of `@teechat/inference-engine` `src/sev-snp/measurements.ts` and
//! `src/sev-snp/build-attestation.ts` (minus guest report I/O).

mod bundle;
mod claims;
mod error;
mod measurements;
mod tcb_pins;

pub use bundle::{build_attestation_bundle_from_measurements, BuildAttestationBundleArgs};
pub use claims::QuoteClaims;
pub use error::AttestationError;
pub use measurements::{
    resolve_binary_measurements_from_env, BinaryMeasurements, OpeIdentityMeasurements,
    AttestedMtlsIdentityMeasurements,
};
pub use tcb_pins::{load_tcb_pins, validate_tcb_pins, TcbPins, TcbPinsValidation};
