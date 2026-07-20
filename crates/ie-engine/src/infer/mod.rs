//! OPE inference handler (port of `engine-plane/inference-handler.ts` + `server/ope-inference.ts`).

mod gate;
mod gateway_plane_task;
mod ope_inference;

pub use gate::{
    ope_inference_reject_body, validate_ope_inference_content_type, validate_ope_inference_envelope,
    GateResult, OpeInferenceGateError,
};
pub use gateway_plane_task::is_gateway_plane_task_envelope;
pub use ope_inference::{
    run_ope_inference_on_envelope, NdjsonStreamWriter, OpeInferenceOptions, OpeInferenceResult,
};
