//! Production OPE inference path (port of `server/ope-inference.ts`).

use std::sync::Arc;

use futures::StreamExt;
use ie_crypto::CryptoProvider;
use ie_protocol::{
    encode_ope_stream_line, OpeEnvelope, OpeStreamFrame, CONTENT_TYPE_OPE_JSON,
    CONTENT_TYPE_OPE_JSON_STREAM,
};
use ie_upstream::{
    clamp_vllm_max_tokens, VllmChatClient, VllmStreamOptions, VLLM_MAX_TOKENS_DEFAULT,
};
use serde_json::{json, Value};
use tracing::warn;

use crate::ops::{conversation_kv_key, plan_vllm_prefill, ConversationKvState};

use super::gate::{
    ope_inference_reject_body, validate_ope_inference_envelope, GateResult,
};

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
    pub vllm: VllmChatClient,
    pub chunk_chars: usize,
    pub kv: Option<std::sync::Mutex<std::collections::HashMap<String, ConversationKvState>>>,
    /// Ed25519 signing key for usage reports (required for non-empty usage headers).
    pub usage_signing_key: Option<ed25519_dalek::SigningKey>,
}

fn resolve_decrypt_handle(
    options: &OpeInferenceOptions,
    envelope: &OpeEnvelope,
) -> Result<u64, String> {
    if let Some(rotating) = &options.rotating {
        rotating
            .resolve_handle(envelope)
            .map_err(|e| e.to_string())
    } else {
        Ok(options.decrypt_handle)
    }
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

fn prompt_tokens_from_messages(messages: &[Value]) -> u64 {
    let text: String = messages
        .iter()
        .map(|m| {
            m.get("content")
                .map(|c| match c {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .unwrap_or_default()
        })
        .collect::<Vec<_>>()
        .join(" ");
    tokens_from_text(&text)
}

/// Decrypt → vLLM stream → encrypt OPE response chunks (JSON or NDJSON).
///
/// When `ndjson_out` is `Some`, ciphertext frames are appended as NDJSON lines.
pub async fn run_ope_inference_on_envelope(
    envelope: &OpeEnvelope,
    options: &OpeInferenceOptions,
    mut ndjson_out: Option<&mut dyn NdjsonStreamWriter>,
) -> OpeInferenceResult {
    if super::gateway_plane_task::is_gateway_plane_task_envelope(envelope) {
        return super::gateway_plane_task::run_gateway_plane_task_inference(
            envelope,
            &options.vllm_base_url,
            options.vllm_api_key.clone(),
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

    if options.vllm_base_url.trim().is_empty() {
        return OpeInferenceResult {
            status: 503,
            content_type: "application/json".into(),
            body: json!({ "error": "vllm_not_configured" }).to_string(),
            usage_header: None,
        };
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
    let model = strip_model_provider(model_raw);
    let messages = payload
        .get("messages")
        .and_then(|m| m.as_array())
        .cloned()
        .unwrap_or_default();
    let prompt_tokens = prompt_tokens_from_messages(&messages);

    let hash = {
        use sha2::{Digest, Sha256};
        format!("{:x}", Sha256::digest(conv_id.as_bytes()))
    };
    let kv_key = conversation_kv_key(&conv_id, &model);
    let cold_suffix = if let Some(kv) = &options.kv {
        let mut map = kv.lock().expect("kv");
        let prev = map.get(&kv_key).cloned();
        let (plan, next) = plan_vllm_prefill(prev.as_ref(), prompt_tokens, &hash);
        map.insert(kv_key, next);
        plan.cold_suffix_tokens
    } else {
        prompt_tokens
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

    if let Some(out) = ndjson_out.as_mut() {
        if let Ok(line) = encode_ope_stream_line(&OpeStreamFrame::server_share(&resp.server_share)) {
            out.write(&line);
        }
    }

    let max_tokens = payload
        .get("max_tokens")
        .and_then(|v| v.as_u64())
        .map(|n| clamp_vllm_max_tokens(n as u32));

    let stream = options
        .vllm
        .stream_chat_completion(VllmStreamOptions {
            base_url: options.vllm_base_url.clone(),
            model: model.clone(),
            messages,
            api_key: options.vllm_api_key.clone(),
            max_tokens: max_tokens.or(Some(VLLM_MAX_TOKENS_DEFAULT)),
            frequency_penalty: payload.get("frequency_penalty").and_then(|v| v.as_f64()),
            presence_penalty: payload.get("presence_penalty").and_then(|v| v.as_f64()),
            temperature: payload.get("temperature").and_then(|v| v.as_f64()),
            top_p: payload.get("top_p").and_then(|v| v.as_f64()),
            enable_thinking: payload
                .get("enable_thinking")
                .and_then(|v| v.as_bool())
                .or(Some(true)),
        })
        .await;

    let stream = match stream {
        Ok(s) => s,
        Err(e) => {
            options.provider.free_response(resp.session);
            if streaming {
                return OpeInferenceResult {
                    status: 502,
                    content_type: CONTENT_TYPE_OPE_JSON_STREAM.into(),
                    body: String::new(),
                    usage_header: None,
                };
            }
            return OpeInferenceResult {
                status: 502,
                content_type: "application/json".into(),
                body: json!({ "error": "vllm_upstream_failed", "detail": e.to_string() })
                    .to_string(),
                usage_header: None,
            };
        }
    };

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
                if streaming {
                    return OpeInferenceResult {
                        status: 502,
                        content_type: CONTENT_TYPE_OPE_JSON_STREAM.into(),
                        body: String::new(),
                        usage_header: None,
                    };
                }
                return OpeInferenceResult {
                    status: 502,
                    content_type: "application/json".into(),
                    body: json!({ "error": "vllm_upstream_failed", "detail": e.to_string() })
                        .to_string(),
                    usage_header: None,
                };
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

    let completion_tokens = tokens_from_text(if full_text.is_empty() {
        "x"
    } else {
        &full_text
    });
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
        ts: chrono::Utc::now().to_rfc3339(),
    };
    let usage_header = match &options.usage_signing_key {
        Some(key) => {
            let sig = crate::ops::sign_usage_report(key, &report);
            let signed = ie_protocol::SignedUsageReport { report, sig };
            Some(ope_crypto::encode(
                serde_json::to_string(&signed).unwrap_or_default().as_bytes(),
            ))
        }
        None => {
            warn!("usage_signing_key missing; omitting usage header");
            None
        }
    };

    if streaming {
        if let Some(out) = ndjson_out.as_mut() {
            if let Ok(line) = encode_ope_stream_line(&OpeStreamFrame::trailer(usage_header.clone())) {
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
            "engine_prefill_tokens": cold_suffix,
        })
        .to_string(),
        usage_header,
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
