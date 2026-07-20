//! Normalize multimodal chat messages for OpenAI-compatible vLLM (port of `vllm-multimodal.ts`).

use serde_json::{json, Value};

/// Normalize decrypted OPE messages for OpenAI-compatible vLLM upstream.
pub fn normalize_vllm_messages(messages: &[Value]) -> Vec<Value> {
    messages
        .iter()
        .map(|m| {
            let role = m
                .get("role")
                .and_then(|r| r.as_str())
                .unwrap_or("user")
                .to_string();
            let content = m.get("content");
            match content {
                Some(Value::String(s)) => json!({ "role": role, "content": s }),
                Some(Value::Array(parts)) => {
                    let mut out_parts = Vec::new();
                    for part in parts {
                        let Some(obj) = part.as_object() else {
                            continue;
                        };
                        let ty = obj.get("type").and_then(|t| t.as_str());
                        match ty {
                            Some("text") => {
                                if let Some(text) = obj.get("text").and_then(|t| t.as_str()) {
                                    out_parts.push(json!({ "type": "text", "text": text }));
                                }
                            }
                            Some("image_url") => {
                                if let Some(url) = obj
                                    .get("image_url")
                                    .and_then(|u| u.get("url"))
                                    .and_then(|u| u.as_str())
                                {
                                    out_parts.push(json!({
                                        "type": "image_url",
                                        "image_url": { "url": url }
                                    }));
                                }
                            }
                            _ => {}
                        }
                    }
                    if out_parts.is_empty() {
                        json!({
                            "role": role,
                            "content": content.map(|c| c.to_string()).unwrap_or_default()
                        })
                    } else {
                        json!({ "role": role, "content": out_parts })
                    }
                }
                Some(other) => json!({ "role": role, "content": other.to_string() }),
                None => json!({ "role": role, "content": "" }),
            }
        })
        .collect()
}

/// Rough prompt-token estimate (chars/4 + 512 per image), matching TS.
pub fn estimate_prompt_tokens_from_messages(messages: &[Value]) -> u64 {
    let mut chars: u64 = 0;
    let mut images: u64 = 0;
    for m in messages {
        match m.get("content") {
            Some(Value::String(s)) => chars += s.len() as u64,
            Some(Value::Array(parts)) => {
                for part in parts {
                    let Some(obj) = part.as_object() else {
                        continue;
                    };
                    match obj.get("type").and_then(|t| t.as_str()) {
                        Some("text") => {
                            if let Some(text) = obj.get("text").and_then(|t| t.as_str()) {
                                chars += text.len() as u64;
                            }
                        }
                        Some("image_url") => images += 1,
                        _ => {}
                    }
                }
            }
            Some(other) => chars += other.to_string().len() as u64,
            None => {}
        }
    }
    ((chars as f64 / 4.0).ceil() as u64)
        .saturating_add(images.saturating_mul(512))
        .max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_keeps_string_content() {
        let msgs = vec![json!({"role": "user", "content": "hi"})];
        let out = normalize_vllm_messages(&msgs);
        assert_eq!(out[0]["content"], "hi");
    }

    #[test]
    fn normalize_multimodal_parts() {
        let msgs = vec![json!({
            "role": "user",
            "content": [
                {"type": "text", "text": "look"},
                {"type": "image_url", "image_url": {"url": "data:image/png;base64,xx"}}
            ]
        })];
        let out = normalize_vllm_messages(&msgs);
        assert!(out[0]["content"].is_array());
        assert_eq!(out[0]["content"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn estimate_counts_images() {
        let msgs = normalize_vllm_messages(&[json!({
            "role": "user",
            "content": [
                {"type": "text", "text": "abcd"},
                {"type": "image_url", "image_url": {"url": "http://x"}}
            ]
        })]);
        // ceil(4/4)=1 + 512 = 513
        assert_eq!(estimate_prompt_tokens_from_messages(&msgs), 513);
    }
}
