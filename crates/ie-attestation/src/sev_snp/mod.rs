mod build_attestation;
mod guest_report;
mod launch_digest;
mod quote;
mod verify_report;

pub use build_attestation::{
    build_engine_attestation_bundle, build_engine_epoch_attestation_bundle,
};
pub use guest_report::{
    is_sev_snp_guest_device_available, request_sev_snp_attestation_report,
    should_use_sev_snp_attestation,
};
pub use launch_digest::{
    challenge_canonical_launch_digest, extract_measurement_from_report, launch_digest_from_report,
};
pub use quote::{
    bind_epoch_report_data_64, bind_report_data_64, encode_sev_snp_quote_wrapper,
    parse_sev_snp_quote_wrapper, verify_wrapper_report_data, SevSnpQuoteWrapper,
};
pub use verify_report::{extract_report_data_from_report, verify_sev_snp_attestation_report};
