use serde_json::Value;

/// TeeChat client fold boundary (must match `STREAM_THINKING_SEPARATOR` in TeaChat).
pub const STREAM_THINKING_SEPARATOR: &str = "\n\n<!-- teechat:thinking-end -->\n\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VllmTextKind {
    Reasoning,
    Content,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VllmTextDelta {
    pub kind: VllmTextKind,
    pub text: String,
}

/// Extract typed assistant deltas from one vLLM/OpenAI streaming choice.
///
/// vLLM reasoning parsers emit either `delta.reasoning` (current) or
/// `delta.reasoning_content` (older docs). Both are accepted.
pub fn stream_deltas_from_vllm_choice(choice: &Value) -> Vec<VllmTextDelta> {
    let mut out = Vec::new();
    if let Some(delta) = choice.get("delta") {
        // Reasoning before content when both appear in one chunk.
        for key in ["reasoning", "reasoning_content"] {
            if let Some(text) = delta.get(key).and_then(|v| v.as_str()) {
                if !text.is_empty() {
                    out.push(VllmTextDelta {
                        kind: VllmTextKind::Reasoning,
                        text: text.to_string(),
                    });
                    break;
                }
            }
        }
        if let Some(content) = delta.get("content").and_then(|v| v.as_str()) {
            if !content.is_empty() {
                out.push(VllmTextDelta {
                    kind: VllmTextKind::Content,
                    text: content.to_string(),
                });
            }
        }
        return out;
    }
    if let Some(message) = choice.get("message") {
        for key in ["reasoning", "reasoning_content"] {
            if let Some(text) = message.get(key).and_then(|v| v.as_str()) {
                if !text.is_empty() {
                    out.push(VllmTextDelta {
                        kind: VllmTextKind::Reasoning,
                        text: text.to_string(),
                    });
                    break;
                }
            }
        }
        if let Some(content) = message.get("content").and_then(|v| v.as_str()) {
            if !content.is_empty() {
                out.push(VllmTextDelta {
                    kind: VllmTextKind::Content,
                    text: content.to_string(),
                });
            }
        }
    }
    out
}

/// vLLM/OpenAI `choices[0].finish_reason` (`stop`, `length`, …). Ignores JSON null / empty.
pub fn finish_reason_from_vllm_choice(choice: &Value) -> Option<String> {
    let raw = choice.get("finish_reason").and_then(|v| v.as_str())?.trim();
    if raw.is_empty() || raw.eq_ignore_ascii_case("null") {
        return None;
    }
    Some(raw.to_ascii_lowercase())
}

/// OPE status `detail` so the desktop/web client can offer Continue on `length`.
pub fn ope_finish_reason_status_detail(finish_reason: &str, output_empty: bool) -> Option<String> {
    let reason = finish_reason.trim();
    if reason.is_empty() || reason.eq_ignore_ascii_case("null") {
        return None;
    }
    Some(if output_empty {
        format!("empty_completion:{reason}")
    } else {
        format!("finish_reason={reason}")
    })
}

/// Flatten choice text (reasoning then content). Prefer [`stream_deltas_from_vllm_choice`]
/// when the caller needs to insert a thinking/answer boundary.
pub fn stream_text_from_vllm_choice(choice: &Value) -> Option<String> {
    let deltas = stream_deltas_from_vllm_choice(choice);
    if deltas.is_empty() {
        return None;
    }
    Some(deltas.into_iter().map(|d| d.text).collect())
}

/// Parse one SSE `data:` payload line (without the `data:` prefix).
pub fn parse_sse_data_line(data: &str) -> Result<Option<Value>, crate::UpstreamError> {
    let trimmed = data.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed == "[DONE]" {
        return Ok(None);
    }
    serde_json::from_str(trimmed)
        .map(Some)
        .map_err(|e| crate::UpstreamError::InvalidSse(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extracts_delta_content() {
        let choice = json!({"delta": {"content": "hello"}});
        assert_eq!(
            stream_text_from_vllm_choice(&choice).as_deref(),
            Some("hello")
        );
    }

    #[test]
    fn extracts_delta_reasoning_field() {
        let choice = json!({"delta": {"reasoning": "plan"}});
        let deltas = stream_deltas_from_vllm_choice(&choice);
        assert_eq!(
            deltas,
            vec![VllmTextDelta {
                kind: VllmTextKind::Reasoning,
                text: "plan".into(),
            }]
        );
    }

    #[test]
    fn extracts_delta_reasoning_content_alias() {
        let choice = json!({"delta": {"reasoning_content": "plan"}});
        let deltas = stream_deltas_from_vllm_choice(&choice);
        assert_eq!(deltas[0].kind, VllmTextKind::Reasoning);
        assert_eq!(deltas[0].text, "plan");
    }

    #[test]
    fn ignores_empty_content_string() {
        let choice = json!({"delta": {"content": "", "reasoning": "x"}});
        let deltas = stream_deltas_from_vllm_choice(&choice);
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].kind, VllmTextKind::Reasoning);
    }

    #[test]
    fn orders_reasoning_before_content() {
        let choice = json!({"delta": {"content": "hi", "reasoning": "think"}});
        let deltas = stream_deltas_from_vllm_choice(&choice);
        assert_eq!(deltas[0].kind, VllmTextKind::Reasoning);
        assert_eq!(deltas[1].kind, VllmTextKind::Content);
    }

    #[test]
    fn finish_reason_reads_length_and_ignores_null() {
        assert_eq!(
            finish_reason_from_vllm_choice(&json!({"finish_reason": "length"})).as_deref(),
            Some("length")
        );
        assert_eq!(
            finish_reason_from_vllm_choice(&json!({"finish_reason": "STOP"})).as_deref(),
            Some("stop")
        );
        assert_eq!(
            finish_reason_from_vllm_choice(&json!({"finish_reason": serde_json::Value::Null})),
            None
        );
    }

    #[test]
    fn ope_status_detail_marks_length_for_continue() {
        assert_eq!(
            ope_finish_reason_status_detail("length", false).as_deref(),
            Some("finish_reason=length")
        );
        assert_eq!(
            ope_finish_reason_status_detail("length", true).as_deref(),
            Some("empty_completion:length")
        );
    }
}
