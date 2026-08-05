//! Gateway ↔ engine OPE wire protocol.
//!
//! Thin re-export of OPE [`ope_protocol`] (Rust SoT in Lightec-AI/OPE).
//! Prefer depending on `ope-protocol` directly in new code.

pub use ope_protocol::*;

/// Work-pull response header distinguishing inference envelopes from ARCH-CHAL work.
pub const HEADER_OPE_WORK_KIND: &str = "x-ope-work-kind";
pub const OPE_WORK_KIND_INFERENCE: &str = "inference";
pub const OPE_WORK_KIND_CHALLENGE: &str = "challenge";

/// Engine → gateway ARCH-CHAL result POST.
pub const ENGINE_PLANE_PATH_CHALLENGE_RESULT: &str = "/v1/ope/challenge/result";
