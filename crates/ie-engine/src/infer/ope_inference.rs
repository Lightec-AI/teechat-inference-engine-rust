//! Production OPE inference path (port of `server/ope-inference.ts`).

use std::sync::Arc;

use futures::StreamExt;
use ie_crypto::{CryptoError, CryptoProvider, EnvelopeAdmitter};
use ie_protocol::{
    encode_ope_stream_line, OpeEnvelope, OpeStreamFrame, CONTENT_TYPE_OPE_JSON,
    CONTENT_TYPE_OPE_JSON_STREAM,
};
use ie_upstream::{
    clamp_vllm_max_tokens, estimate_prompt_tokens_from_messages, normalize_vllm_messages,
    resolve_vllm_base_url_for_model, EmbeddingsCompleteOptions, VllmChatClient, VllmStreamOptions,
    VLLM_MAX_TOKENS_DEFAULT,
};
use serde_json::{json, Value};
use tracing::warn;

use crate::ops::{conversation_kv_key, plan_vllm_prefill, ConversationKvState, PrefillPlan};

use super::gate::{ope_inference_reject_body, validate_ope_inference_envelope, GateResult};

/// Optional NDJSON sink (OPE §7). Prefer a byte buffer to keep borrow checker happy.
pub trait NdjsonStreamWriter: Send {
    fn write(&mut self, chunk: &[u8]);
    fn end(&mut self);
}

impl NdjsonStreamWriter for Vec<u8> {
    fn write(&mut self, chunk: &[u8]) {
        self.extend_from_slice(chunk);
    }
    fn end(&mut self) {}
}

pub struct OpeInferenceOptions {
    pub request_id: Option<String>,
    /// Fixed decrypt handle when [`Self::rotating`] is `None` (tests / single-epoch).
    pub decrypt_handle: u64,
    /// Prefer envelope-bound epoch resolution when set (production supervised pool).
    pub rotating: Option<Arc<crate::epoch::RotatingEpochDecryptor>>,
    pub provider: Arc<dyn CryptoProvider>,
    pub vllm_base_url: String,
    pub vllm_api_key: Option<String>,
    /// Task vLLM upstream (localhost :8001) for background / E4B model ids.
    pub task_vllm_base_url: Option<String>,
    pub task_vllm_api_key: Option<String>,
    /// Model id served on the task upstream (`TEECHAT_TASK_MODEL`).
    pub task_model_id: Option<String>,
    /// CPU TEI / OpenAI-compatible embeddings upstream (engine loopback).
    pub embeddings_base_url: Option<String>,
    pub embeddings_api_key: Option<String>,
    /// Fallback model id when the decrypted payload omits `model`.
    pub embeddings_default_model: Option<String>,
    pub vllm: VllmChatClient,
    pub chunk_chars: usize,
    /// Shared across pull workers so KV prefill warms survive session affinity.
    pub kv: Option<Arc<std::sync::Mutex<std::collections::HashMap<String, ConversationKvState>>>>,
    /// Ed25519 signing key for usage reports (required for non-empty usage headers).
    pub usage_signing_key: Option<ed25519_dalek::SigningKey>,
    /// RB-05: optional envelope admission before decrypt (`None` = legacy).
    pub admitter: Option<Arc<EnvelopeAdmitter>>,
}

fn resolve_decrypt_handle(
    options: &OpeInferenceOptions,
    envelope: &OpeEnvelope,
) -> Result<u64, String> {
    if let Some(rotating) = &options.rotating {
        rotating.resolve_handle(envelope).map_err(|e| e.to_string())
    } else {
        Ok(options.decrypt_handle)
    }
}

/// Usage reports are signed by the epoch that served the request, so the
/// gateway can check them against the key the same epoch's evidence attested
/// (RB-52). `usage_signing_key` remains for single-epoch test setups.
fn resolve_usage_signing_key(
    options: &OpeInferenceOptions,
    envelope: &OpeEnvelope,
) -> Option<ed25519_dalek::SigningKey> {
    if let Some(rotating) = &options.rotating {
        if let Some(key) = rotating.resolve_usage_signing_key(envelope) {
            return Some((*key).clone());
        }
    }
    options.usage_signing_key.clone()
}

#[derive(Debug, Clone)]
pub struct OpeInferenceResult {
    pub status: u16,
    pub content_type: String,
    pub body: String,
    pub usage_header: Option<String>,
}

fn tokens_from_text(text: &str) -> u64 {
    ((text.len() as f64 / 4.0).ceil() as u64).max(1)
}

fn strip_model_provider(model: &str) -> String {
    match model.find('@') {
        Some(at) => model[..at].to_string(),
        None => model.to_string(),
    }
}

/// Detect OpenAI embeddings vs chat after decrypt (TS `isEmbeddingsRequest` parity).
///
/// Prefers payload shape (`input` without chat `messages`) because typed
/// `OpeEnvelopeMeta` does not yet carry `openai_path`.
pub fn is_embeddings_request(payload: &Value) -> bool {
    let has_input = payload.get("input").is_some();
    if !has_input {
        return false;
    }
    match payload.get("messages") {
        None => true,
        Some(Value::Array(a)) if a.is_empty() => true,
        Some(Value::Null) => true,
        _ => false,
    }
}

/// Decrypt → vLLM/TEI → encrypt OPE response chunks (JSON or NDJSON).
///
/// When `ndjson_out` is `Some`, ciphertext frames are appended as NDJSON lines.
pub async fn run_ope_inference_on_envelope(
    envelope: &OpeEnvelope,
    options: &OpeInferenceOptions,
    mut ndjson_out: Option<&mut dyn NdjsonStreamWriter>,
) -> OpeInferenceResult {
    if super::gateway_plane_task::is_gateway_plane_task_envelope(envelope) {
        let model = envelope
            .meta
            .as_ref()
            .and_then(|m| m.model.as_deref())
            .unwrap_or("unknown");
        let (base_url, _model, api_key, _is_task) = resolve_vllm_base_url_for_model(
            model,
            &options.vllm_base_url,
            options.vllm_api_key.as_deref(),
            options.task_model_id.as_deref(),
            options.task_vllm_base_url.as_deref(),
            options.task_vllm_api_key.as_deref(),
        );
        return super::gateway_plane_task::run_gateway_plane_task_inference(
            envelope,
            &base_url,
            api_key,
            &options.vllm,
            options.request_id.as_deref(),
        )
        .await;
    }

    match validate_ope_inference_envelope(envelope) {
        GateResult::Ok => {}
        GateResult::Reject {
            status,
            error,
            detail,
        } => {
            return OpeInferenceResult {
                status,
                content_type: "application/json".into(),
                body: ope_inference_reject_body(error.as_str(), detail.as_deref()),
                usage_header: None,
            };
        }
    }

    if let Some(admitter) = &options.admitter {
        match admitter.admit(envelope) {
            Ok(_) => {}
            Err(CryptoError::Admit(code, detail)) => {
                return OpeInferenceResult {
                    status: 401,
                    content_type: "application/json".into(),
                    body: json!({ "error": code, "detail": detail }).to_string(),
                    usage_header: None,
                };
            }
            Err(e) => {
                return OpeInferenceResult {
                    status: 400,
                    content_type: "application/json".into(),
                    body: json!({ "error": "ope_admit_failed", "detail": e.to_string() }).to_string(),
                    usage_header: None,
                };
            }
        }
    }

    let decrypt_handle = match resolve_decrypt_handle(options, envelope) {
        Ok(h) => h,
        Err(e) => {
            return OpeInferenceResult {
                status: 400,
                content_type: "application/json".into(),
                body: json!({ "error": "decrypt_failed", "detail": e }).to_string(),
                usage_header: None,
            };
        }
    };

    let payload = match options.provider.decrypt_request(decrypt_handle, envelope) {
        Ok(v) => v,
        Err(e) => {
            return OpeInferenceResult {
                status: 400,
                content_type: "application/json".into(),
                body: json!({ "error": "decrypt_failed", "detail": e.to_string() }).to_string(),
                usage_header: None,
            };
        }
    };

    if is_embeddings_request(&payload) {
        let Some(base_url) = options
            .embeddings_base_url
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            return OpeInferenceResult {
                status: 503,
                content_type: "application/json".into(),
                body: json!({ "error": "embeddings_not_configured" }).to_string(),
                usage_header: None,
            };
        };
        return run_embeddings_inference(envelope, &payload, options, base_url, &mut ndjson_out)
            .await;
    }

    if options.vllm_base_url.trim().is_empty() {
        return OpeInferenceResult {
            status: 503,
            content_type: "application/json".into(),
            body: json!({ "error": "vllm_not_configured" }).to_string(),
            usage_header: None,
        };
    }

    run_chat_inference(envelope, &payload, options, decrypt_handle, ndjson_out).await
}

async fn run_embeddings_inference(
    envelope: &OpeEnvelope,
    payload: &Value,
    options: &OpeInferenceOptions,
    embeddings_base_url: &str,
    ndjson_out: &mut Option<&mut dyn NdjsonStreamWriter>,
) -> OpeInferenceResult {
    let decrypt_handle = match resolve_decrypt_handle(options, envelope) {
        Ok(h) => h,
        Err(e) => {
            return OpeInferenceResult {
                status: 400,
                content_type: "application/json".into(),
                body: json!({ "error": "decrypt_failed", "detail": e }).to_string(),
                usage_header: None,
            };
        }
    };

    let conv_id = envelope
        .meta
        .as_ref()
        .and_then(|m| m.conversation_id.clone())
        .unwrap_or_else(|| "conv".into());
    let model_raw = payload
        .get("model")
        .and_then(|m| m.as_str())
        .or_else(|| envelope.meta.as_ref().and_then(|m| m.model.as_deref()))
        .or(options.embeddings_default_model.as_deref())
        .unwrap_or("unknown");
    let model = strip_model_provider(model_raw);

    let mut extra = json!({});
    if let Some(dims) = payload.get("dimensions").and_then(|v| v.as_u64()) {
        extra["dimensions"] = json!(dims);
    }
    if let Some(fmt) = payload.get("encoding_format").and_then(|v| v.as_str()) {
        extra["encoding_format"] = json!(fmt);
    }
    let extra = if extra.as_object().map(|o| !o.is_empty()).unwrap_or(false) {
        Some(extra)
    } else {
        None
    };

    let input = payload
        .get("input")
        .cloned()
        .unwrap_or(Value::String(String::new()));

    // Call TEI before writing any OPE stream bytes (chat parity for status mapping).
    let completed = options
        .vllm
        .complete_embeddings(EmbeddingsCompleteOptions {
            base_url: embeddings_base_url.to_string(),
            api_key: options.embeddings_api_key.clone(),
            model: model.clone(),
            input,
            extra,
        })
        .await;

    let completed = match completed {
        Ok(c) => c,
        Err(e) => {
            return embeddings_upstream_failed_result(&e);
        }
    };

    let resp = match options.provider.begin_response(decrypt_handle, envelope) {
        Ok(r) => r,
        Err(e) => {
            return OpeInferenceResult {
                status: 400,
                content_type: "application/json".into(),
                body: json!({ "error": "begin_response_failed", "detail": e.to_string() })
                    .to_string(),
                usage_header: None,
            };
        }
    };

    let streaming = ndjson_out.is_some();
    if let Some(out) = ndjson_out.as_mut() {
        if let Ok(line) = encode_ope_stream_line(&OpeStreamFrame::server_share(&resp.server_share))
        {
            out.write(&line);
        }
    }

    let json_text = completed.body.to_string();
    let mut chunks: Vec<String> = Vec::new();
    let mut seq: u32 = 0;
    encrypt_piece(
        options.provider.as_ref(),
        resp.session,
        &json_text,
        true,
        &mut seq,
        &mut chunks,
        ndjson_out,
    );
    options.provider.free_response(resp.session);

    let report = ie_protocol::UsageReport {
        request_id: options
            .request_id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        conversation_id: conv_id,
        engine_id: envelope
            .engine_id
            .clone()
            .unwrap_or_else(|| "engine".into()),
        prompt_tokens: completed.prompt_tokens,
        completion_tokens: 0,
        cached_tokens: 0,
        ts: chrono::Utc::now().to_rfc3339(),
    };
    let usage_header = match resolve_usage_signing_key(options, envelope) {
        Some(key) => {
            let sig = crate::ops::sign_usage_report(&key, &report);
            let signed = ie_protocol::SignedUsageReport { report, sig };
            Some(ope_crypto::encode(
                serde_json::to_string(&signed)
                    .unwrap_or_default()
                    .as_bytes(),
            ))
        }
        None => {
            warn!("usage_signing_key missing; omitting usage header");
            None
        }
    };

    if streaming {
        if let Some(out) = ndjson_out.as_mut() {
            if let Ok(line) = encode_ope_stream_line(&OpeStreamFrame::trailer(usage_header.clone()))
            {
                out.write(&line);
            }
            out.end();
        }
        return OpeInferenceResult {
            status: 200,
            content_type: CONTENT_TYPE_OPE_JSON_STREAM.into(),
            body: String::new(),
            usage_header,
        };
    }

    OpeInferenceResult {
        status: 200,
        content_type: CONTENT_TYPE_OPE_JSON.into(),
        body: json!({
            "server_share": resp.server_share,
            "chunks": chunks,
            "engine_prefill_tokens": 0,
        })
        .to_string(),
        usage_header,
    }
}

async fn run_chat_inference(
    envelope: &OpeEnvelope,
    payload: &Value,
    options: &OpeInferenceOptions,
    decrypt_handle: u64,
    mut ndjson_out: Option<&mut dyn NdjsonStreamWriter>,
) -> OpeInferenceResult {
    let conv_id = envelope
        .meta
        .as_ref()
        .and_then(|m| m.conversation_id.clone())
        .unwrap_or_else(|| "conv".into());
    let model_raw = payload
        .get("model")
        .and_then(|m| m.as_str())
        .or_else(|| envelope.meta.as_ref().and_then(|m| m.model.as_deref()))
        .unwrap_or("unknown");
    let (vllm_base_url, model, vllm_api_key, is_task_model) = resolve_vllm_base_url_for_model(
        model_raw,
        &options.vllm_base_url,
        options.vllm_api_key.as_deref(),
        options.task_model_id.as_deref(),
        options.task_vllm_base_url.as_deref(),
        options.task_vllm_api_key.as_deref(),
    );
    let messages = normalize_vllm_messages(
        payload
            .get("messages")
            .and_then(|m| m.as_array())
            .map(|a| a.as_slice())
            .unwrap_or(&[]),
    );
    let estimated_prompt_tokens = estimate_prompt_tokens_from_messages(&messages);

    let hash = {
        use sha2::{Digest, Sha256};
        format!("{:x}", Sha256::digest(conv_id.as_bytes()))
    };
    let kv_key = conversation_kv_key(&conv_id, &model);
    let plan = if let Some(kv) = &options.kv {
        let mut map = kv.lock().expect("kv");
        let prev = map.get(&kv_key).cloned();
        let (plan, next) = plan_vllm_prefill(prev.as_ref(), estimated_prompt_tokens, &hash);
        map.insert(kv_key, next);
        plan
    } else {
        PrefillPlan {
            warm_prefix_tokens: 0,
            cold_suffix_tokens: estimated_prompt_tokens,
        }
    };

    let resp = match options.provider.begin_response(decrypt_handle, envelope) {
        Ok(r) => r,
        Err(e) => {
            return OpeInferenceResult {
                status: 400,
                content_type: "application/json".into(),
                body: json!({ "error": "begin_response_failed", "detail": e.to_string() })
                    .to_string(),
                usage_header: None,
            };
        }
    };

    let chunk_chars = if options.chunk_chars == 0 {
        8
    } else {
        options.chunk_chars
    };
    let mut chunks: Vec<String> = Vec::new();
    let mut pending = String::new();
    let mut full_text = String::new();
    let mut seq: u32 = 0;
    let streaming = ndjson_out.is_some();

    let max_tokens = payload
        .get("max_tokens")
        .and_then(|v| v.as_u64())
        .map(|n| clamp_vllm_max_tokens(n as u32));

    // Open vLLM *before* writing any OPE stream bytes. Previously we emitted
    // `server_share` first, then on context-length / upstream HTTP errors still
    // finished an empty `ope+json-stream` with x-ope-status 200 — OpenAPI
    // synthesized HTTP 200 + empty assistant content (silent drop for long context).
    let stream = options
        .vllm
        .stream_chat_completion(VllmStreamOptions {
            base_url: vllm_base_url,
            model: model.clone(),
            messages,
            api_key: vllm_api_key,
            max_tokens: max_tokens.or(Some(VLLM_MAX_TOKENS_DEFAULT)),
            frequency_penalty: payload.get("frequency_penalty").and_then(|v| v.as_f64()),
            presence_penalty: payload.get("presence_penalty").and_then(|v| v.as_f64()),
            temperature: payload.get("temperature").and_then(|v| v.as_f64()),
            top_p: payload.get("top_p").and_then(|v| v.as_f64()),
            // Task model must stay non-thinking (titles / search prep / digests).
            enable_thinking: payload
                .get("enable_thinking")
                .and_then(|v| v.as_bool())
                .or(Some(!is_task_model)),
        })
        .await;

    let (stream, usage_state) = match stream {
        Ok(pair) => pair,
        Err(e) => {
            options.provider.free_response(resp.session);
            return vllm_upstream_failed_result(&e);
        }
    };

    // vLLM accepted the request — now it is safe to start the OPE ciphertext stream.
    if let Some(out) = ndjson_out.as_mut() {
        if let Ok(line) = encode_ope_stream_line(&OpeStreamFrame::server_share(&resp.server_share))
        {
            out.write(&line);
        }
    }

    tokio::pin!(stream);
    while let Some(item) = stream.next().await {
        match item {
            Ok(delta) => {
                full_text.push_str(&delta);
                pending.push_str(&delta);
                while pending.len() >= chunk_chars {
                    let piece: String = pending.chars().take(chunk_chars).collect();
                    let rest: String = pending.chars().skip(chunk_chars).collect();
                    pending = rest;
                    encrypt_piece(
                        options.provider.as_ref(),
                        resp.session,
                        &piece,
                        false,
                        &mut seq,
                        &mut chunks,
                        &mut ndjson_out,
                    );
                }
            }
            Err(e) => {
                options.provider.free_response(resp.session);
                warn!(error = %e, "vllm stream error");
                // If we already wrote ciphertext, pull finishes the open stream (partial
                // tokens). JSON error is only useful when nothing was flushed yet.
                if streaming && seq > 0 {
                    return OpeInferenceResult {
                        status: 502,
                        content_type: CONTENT_TYPE_OPE_JSON_STREAM.into(),
                        body: String::new(),
                        usage_header: None,
                    };
                }
                return vllm_upstream_failed_result(&e);
            }
        }
    }

    if !pending.is_empty() {
        encrypt_piece(
            options.provider.as_ref(),
            resp.session,
            &pending,
            true,
            &mut seq,
            &mut chunks,
            &mut ndjson_out,
        );
    }

    options.provider.free_response(resp.session);

    let usage = usage_state
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let completion_tokens = match usage.completion_tokens {
        Some(n) => n,
        None => tokens_from_text(if full_text.is_empty() {
            "x"
        } else {
            &full_text
        }),
    };
    let prompt_tokens = match usage.prompt_tokens {
        Some(n) if n > 0 => n,
        _ => (plan.warm_prefix_tokens + plan.cold_suffix_tokens).max(1),
    };
    let cached_tokens = match usage.cached_tokens {
        Some(n) => n,
        None => plan.warm_prefix_tokens,
    };
    let report = ie_protocol::UsageReport {
        request_id: options
            .request_id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        conversation_id: conv_id,
        engine_id: envelope
            .engine_id
            .clone()
            .unwrap_or_else(|| "engine".into()),
        prompt_tokens,
        completion_tokens,
        cached_tokens,
        ts: chrono::Utc::now().to_rfc3339(),
    };
    let usage_header = match resolve_usage_signing_key(options, envelope) {
        Some(key) => {
            let sig = crate::ops::sign_usage_report(&key, &report);
            let signed = ie_protocol::SignedUsageReport { report, sig };
            Some(ope_crypto::encode(
                serde_json::to_string(&signed)
                    .unwrap_or_default()
                    .as_bytes(),
            ))
        }
        None => {
            warn!("usage_signing_key missing; omitting usage header");
            None
        }
    };

    if streaming {
        if let Some(out) = ndjson_out.as_mut() {
            if let Ok(line) = encode_ope_stream_line(&OpeStreamFrame::trailer(usage_header.clone()))
            {
                out.write(&line);
            }
            out.end();
        }
        return OpeInferenceResult {
            status: 200,
            content_type: CONTENT_TYPE_OPE_JSON_STREAM.into(),
            body: String::new(),
            usage_header,
        };
    }

    OpeInferenceResult {
        status: 200,
        content_type: CONTENT_TYPE_OPE_JSON.into(),
        body: json!({
            "server_share": resp.server_share,
            "chunks": chunks,
            "engine_prefill_tokens": plan.cold_suffix_tokens,
        })
        .to_string(),
        usage_header,
    }
}

fn vllm_upstream_failed_result(err: &ie_upstream::UpstreamError) -> OpeInferenceResult {
    let status = match err {
        ie_upstream::UpstreamError::Http { status, .. } if (400..500).contains(status) => *status,
        _ => 502,
    };
    OpeInferenceResult {
        status,
        // Must NOT be ope+json-stream: pull aborts the speculative stream open and
        // re-POSTs this JSON with the real x-ope-status (see plane/pull.rs).
        content_type: "application/json".into(),
        body: json!({ "error": "vllm_upstream_failed", "detail": err.to_string() }).to_string(),
        usage_header: None,
    }
}

fn embeddings_upstream_failed_result(err: &ie_upstream::UpstreamError) -> OpeInferenceResult {
    let status = match err {
        ie_upstream::UpstreamError::Http { status, .. } if (400..500).contains(status) => *status,
        _ => 502,
    };
    OpeInferenceResult {
        status,
        content_type: "application/json".into(),
        body: json!({ "error": "embeddings_upstream_failed", "detail": err.to_string() })
            .to_string(),
        usage_header: None,
    }
}

fn encrypt_piece(
    provider: &dyn CryptoProvider,
    session: u64,
    piece: &str,
    final_: bool,
    seq: &mut u32,
    chunks: &mut Vec<String>,
    ndjson_out: &mut Option<&mut dyn NdjsonStreamWriter>,
) {
    match provider.encrypt_response_chunk(session, *seq, piece.as_bytes()) {
        Ok(ciphertext) => {
            if let Some(out) = ndjson_out.as_mut() {
                if let Ok(line) =
                    encode_ope_stream_line(&OpeStreamFrame::ciphertext(*seq, &ciphertext, final_))
                {
                    out.write(&line);
                }
            } else {
                chunks.push(ciphertext);
            }
            *seq += 1;
        }
        Err(e) => warn!(error = %e, "encrypt_response_chunk failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embeddings_request_detects_input_without_messages() {
        assert!(is_embeddings_request(&json!({
            "model": "Qwen/Qwen3-Embedding-0.6B",
            "input": "hello",
        })));
        assert!(is_embeddings_request(&json!({
            "input": ["a", "b"],
            "messages": [],
        })));
        assert!(!is_embeddings_request(&json!({
            "model": "chat",
            "messages": [{"role": "user", "content": "hi"}],
        })));
        assert!(!is_embeddings_request(&json!({
            "input": "x",
            "messages": [{"role": "user", "content": "hi"}],
        })));
    }
}
