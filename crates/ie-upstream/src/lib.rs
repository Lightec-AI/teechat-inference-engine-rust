//! OpenAI-compatible vLLM upstream client (port of `upstream/vllm-chat.ts`).

mod client;
mod error;
mod sse;

pub use client::{
    build_vllm_chat_body, clamp_open_ai_penalty, clamp_vllm_max_tokens, max_tokens_from_env,
    open_ai_chat_completions_url, vllm_config_from_env, VllmChatClient, VllmCompleteOptions,
    VllmStreamOptions, VLLM_MAX_TOKENS_DEFAULT, VLLM_MAX_TOKENS_MAX, VLLM_MAX_TOKENS_MIN,
};
pub use error::UpstreamError;
pub use sse::{parse_sse_data_line, stream_text_from_vllm_choice};
