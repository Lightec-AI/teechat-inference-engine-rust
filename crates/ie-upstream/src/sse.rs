use serde_json::Value;

/// Extract assistant text from one vLLM/OpenAI streaming chunk.
pub fn stream_text_from_vllm_choice(choice: &Value) -> Option<String> {
    if let Some(delta) = choice.get("delta") {
        if let Some(content) = delta.get("content").and_then(|v| v.as_str()) {
            if !content.is_empty() {
                return Some(content.to_string());
            }
        }
        if let Some(reasoning) = delta.get("reasoning_content").and_then(|v| v.as_str()) {
            if !reasoning.is_empty() {
                return Some(reasoning.to_string());
            }
        }
    }
    if let Some(message) = choice.get("message") {
        if let Some(content) = message.get("content").and_then(|v| v.as_str()) {
            if !content.is_empty() {
                return Some(content.to_string());
            }
        }
    }
    None
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
}
