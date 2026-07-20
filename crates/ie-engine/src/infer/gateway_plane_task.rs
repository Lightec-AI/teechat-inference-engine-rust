//! Gateway-origin background inference (port of `server/gateway-plane-task-inference.ts`).

use ie_protocol::{GatewayPlaneTaskPayload, OpeEnvelope};
use ie_upstream::{clamp_vllm_max_tokens, VllmChatClient, VllmCompleteOptions};
use serde_json::{json, Value};

use super::ope_inference::OpeInferenceResult;

pub const GATEWAY_PLANE_TASK_ENC: &str = "gateway-plane-task";

pub fn is_gateway_plane_task_envelope(envelope: &OpeEnvelope) -> bool {
    envelope.enc == GATEWAY_PLANE_TASK_ENC
}

fn validate_gateway_plane_task_envelope(
    envelope: &OpeEnvelope,
) -> Result<(), (u16, &'static str)> {
    if !is_gateway_plane_task_envelope(envelope) {
        return Err((400, "not_gateway_plane_task"));
    }
    if envelope
        .engine_id
        .as_ref()
        .map(|s| s.trim().is_empty())
        .unwrap_or(true)
    {
        return Err((400, "engine_id_required"));
    }
    let model = envelope
        .meta
        .as_ref()
        .and_then(|m| m.model.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if model.is_none() {
        return Err((400, "model_required"));
    }
    let task = envelope
        .meta
        .as_ref()
        .and_then(|m| m.gateway_task.as_ref())
        .ok_or((400, "gateway_task_messages_required"))?;
    if task.messages.is_empty() {
        return Err((400, "gateway_task_messages_required"));
    }
    for m in &task.messages {
        if m.role.trim().is_empty() {
            return Err((400, "invalid_gateway_task_message"));
        }
    }
    Ok(())
}

fn strip_model_provider(model: &str) -> String {
    match model.find('@') {
        Some(at) => model[..at].to_string(),
        None => model.to_string(),
    }
}

fn tokens_from_text(text: &str) -> u64 {
    ((text.len() as f64 / 4.0).ceil() as u64).max(1)
}

fn messages_to_json(task: &GatewayPlaneTaskPayload) -> Vec<Value> {
    task.messages
        .iter()
        .map(|m| {
            json!({
                "role": m.role,
                "content": m.content,
            })
        })
        .collect()
}

/// Run gateway-plane-task (plaintext meta) via vLLM; return OpenAI-shaped JSON.
pub async fn run_gateway_plane_task_inference(
    envelope: &OpeEnvelope,
    vllm_base_url: &str,
    vllm_api_key: Option<String>,
    vllm: &VllmChatClient,
    request_id: Option<&str>,
) -> OpeInferenceResult {
    if let Err((status, error)) = validate_gateway_plane_task_envelope(envelope) {
        return OpeInferenceResult {
            status,
            content_type: "application/json".into(),
            body: json!({ "error": error }).to_string(),
            usage_header: None,
        };
    }

    if vllm_base_url.trim().is_empty() {
        return OpeInferenceResult {
            status: 503,
            content_type: "application/json".into(),
            body: json!({ "error": "vllm_not_configured" }).to_string(),
            usage_header: None,
        };
    }

    let model = strip_model_provider(
        envelope
            .meta
            .as_ref()
            .and_then(|m| m.model.as_deref())
            .unwrap_or("unknown"),
    );
    let task = envelope
        .meta
        .as_ref()
        .and_then(|m| m.gateway_task.as_ref())
        .expect("validated");
    let messages = messages_to_json(task);
    let prompt_tokens = tokens_from_text(
        &task
            .messages
            .iter()
            .map(|m| m.content.as_str())
            .collect::<Vec<_>>()
            .join(" "),
    );

    let max_tokens = task.max_tokens.map(clamp_vllm_max_tokens);
    let content = match vllm
        .complete_chat(VllmCompleteOptions {
            base_url: vllm_base_url.to_string(),
            model: model.clone(),
            messages,
            api_key: vllm_api_key,
            max_tokens,
            frequency_penalty: None,
            presence_penalty: None,
            temperature: task.temperature.map(|t| t as f64),
            top_p: None,
            enable_thinking: Some(false),
        })
        .await
    {
        Ok(c) => c,
        Err(e) => {
            return OpeInferenceResult {
                status: 502,
                content_type: "application/json".into(),
                body: json!({ "error": "vllm_upstream_failed", "detail": e.to_string() })
                    .to_string(),
                usage_header: None,
            };
        }
    };

    let completion_tokens = tokens_from_text(if content.is_empty() { "x" } else { &content });
    let signed = json!({
        "report": {
            "request_id": request_id.unwrap_or("gateway-task"),
            "conversation_id": envelope.meta.as_ref().and_then(|m| m.conversation_id.as_deref()).unwrap_or("gateway-task"),
            "engine_id": envelope.engine_id.as_deref().unwrap_or("engine"),
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "ts": chrono::Utc::now().to_rfc3339(),
        },
        "sig": "gateway-plane-task",
    });
    let usage_header = Some(ope_crypto::encode(signed.to_string().as_bytes()));

    OpeInferenceResult {
        status: 200,
        content_type: "application/json".into(),
        body: json!({
            "object": "chat.completion",
            "model": model,
            "choices": [{ "message": { "role": "assistant", "content": content } }],
        })
        .to_string(),
        usage_header,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ie_protocol::{GatewayPlaneMessage, OpeEnvelopeMeta};

    fn sample_task() -> OpeEnvelope {
        OpeEnvelope {
            ope_version: "1.0".into(),
            alg: "none".into(),
            enc: GATEWAY_PLANE_TASK_ENC.into(),
            kid: "gateway".into(),
            recipient: "teechat-engine".into(),
            ts: "t".into(),
            nonce: "n".into(),
            payload_hash: "".into(),
            engine_id: Some("engine-rust-canary".into()),
            meta: Some(OpeEnvelopeMeta {
                conversation_id: Some("gateway-task:1".into()),
                model: Some("google/gemma-4-31B-it@teechat".into()),
                tenant: None,
                metering: None,
                route: None,
                traffic_class: Some("live_chat".into()),
                gateway_task: Some(GatewayPlaneTaskPayload {
                    messages: vec![GatewayPlaneMessage {
                        role: "user".into(),
                        content: "hi".into(),
                    }],
                    max_tokens: Some(32),
                    temperature: Some(0.2),
                }),
            }),
            sig: None,
            ciphertext: None,
            iv: None,
            e2e: None,
        }
    }

    #[test]
    fn validates_task_envelope() {
        assert!(validate_gateway_plane_task_envelope(&sample_task()).is_ok());
    }

    #[test]
    fn rejects_e2e_as_task() {
        let mut e = sample_task();
        e.enc = "e2e-hybrid-pq".into();
        assert!(validate_gateway_plane_task_envelope(&e).is_err());
    }
}
