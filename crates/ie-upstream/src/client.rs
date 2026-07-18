use std::collections::HashMap;
use std::pin::Pin;

use futures::{Stream, StreamExt};
use reqwest::Client;
use serde_json::{json, Value};

use crate::sse::{parse_sse_data_line, stream_text_from_vllm_choice};
use crate::UpstreamError;

pub const VLLM_MAX_TOKENS_DEFAULT: u32 = 4096;
pub const VLLM_MAX_TOKENS_MIN: u32 = 256;
pub const VLLM_MAX_TOKENS_MAX: u32 = 32_768;

pub fn clamp_vllm_max_tokens(n: u32) -> u32 {
    n.clamp(VLLM_MAX_TOKENS_MIN, VLLM_MAX_TOKENS_MAX)
}

pub fn max_tokens_from_env(env: &HashMap<String, String>) -> u32 {
    let raw = env
        .get("TEECHAT_OPE_MAX_TOKENS")
        .or_else(|| env.get("TEECHAT_VLLM_MAX_TOKENS"))
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());
    match raw.and_then(|s| s.parse::<u32>().ok()) {
        Some(n) if n > 0 => clamp_vllm_max_tokens(n),
        _ => VLLM_MAX_TOKENS_DEFAULT,
    }
}

pub fn clamp_open_ai_penalty(value: f64) -> f64 {
    if !value.is_finite() {
        return 0.0;
    }
    value.clamp(0.0, 2.0)
}

fn normalize_base_url(base_url: &str) -> String {
    base_url.trim().trim_end_matches('/').to_string()
}

pub fn open_ai_chat_completions_url(base_url: &str) -> String {
    let base = normalize_base_url(base_url);
    if base.ends_with("/v1") {
        format!("{base}/chat/completions")
    } else {
        format!("{base}/v1/chat/completions")
    }
}

pub fn merge_vllm_thinking_into_body(mut body: Value, enable_thinking: bool) -> Value {
    let mut extra = body
        .get("extra_body")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let mut kwargs = extra
        .get("chat_template_kwargs")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if let Some(obj) = kwargs.as_object_mut() {
        obj.insert("enable_thinking".into(), json!(enable_thinking));
    }
    if let Some(obj) = extra.as_object_mut() {
        obj.insert("chat_template_kwargs".into(), kwargs);
    }
    body["extra_body"] = extra;
    body
}

pub fn build_vllm_chat_body(opts: &VllmChatBodyOptions<'_>) -> Value {
    let mut body = json!({
        "model": opts.model,
        "messages": opts.messages,
        "stream": opts.stream,
        "max_tokens": opts.max_tokens.unwrap_or(VLLM_MAX_TOKENS_DEFAULT),
    });
    if let Some(v) = opts.frequency_penalty {
        body["frequency_penalty"] = json!(clamp_open_ai_penalty(v));
    }
    if let Some(v) = opts.presence_penalty {
        body["presence_penalty"] = json!(clamp_open_ai_penalty(v));
    }
    if let Some(v) = opts.temperature {
        body["temperature"] = json!(v);
    }
    if let Some(v) = opts.top_p {
        body["top_p"] = json!(v);
    }
    if let Some(enable) = opts.enable_thinking {
        body = merge_vllm_thinking_into_body(body, enable);
    }
    body
}

pub struct VllmChatBodyOptions<'a> {
    pub model: &'a str,
    pub messages: &'a [Value],
    pub stream: bool,
    pub max_tokens: Option<u32>,
    pub frequency_penalty: Option<f64>,
    pub presence_penalty: Option<f64>,
    pub temperature: Option<f64>,
    pub top_p: Option<f64>,
    pub enable_thinking: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct VllmStreamOptions {
    pub base_url: String,
    pub model: String,
    pub messages: Vec<Value>,
    pub api_key: Option<String>,
    pub max_tokens: Option<u32>,
    pub frequency_penalty: Option<f64>,
    pub presence_penalty: Option<f64>,
    pub temperature: Option<f64>,
    pub top_p: Option<f64>,
    pub enable_thinking: Option<bool>,
}

pub type VllmCompleteOptions = VllmStreamOptions;

pub struct VllmChatClient {
    http: Client,
}

impl Default for VllmChatClient {
    fn default() -> Self {
        Self {
            http: Client::new(),
        }
    }
}

impl VllmChatClient {
    pub fn new(http: Client) -> Self {
        Self { http }
    }

    pub async fn stream_chat_completion(
        &self,
        opts: VllmStreamOptions,
    ) -> Result<impl Stream<Item = Result<String, UpstreamError>> + use<>, UpstreamError> {
        let url = open_ai_chat_completions_url(&opts.base_url);
        let mut req = self.http.post(url).json(&build_vllm_chat_body(&VllmChatBodyOptions {
            model: &opts.model,
            messages: &opts.messages,
            stream: true,
            max_tokens: opts.max_tokens,
            frequency_penalty: opts.frequency_penalty,
            presence_penalty: opts.presence_penalty,
            temperature: opts.temperature,
            top_p: opts.top_p,
            enable_thinking: opts.enable_thinking,
        }));
        if let Some(key) = opts.api_key.as_deref().filter(|k| !k.is_empty()) {
            req = req.bearer_auth(key);
        }

        let res = req.send().await?;
        if !res.status().is_success() {
            let status = res.status().as_u16();
            let body = res.text().await.unwrap_or_default();
            return Err(UpstreamError::Http {
                status,
                body: body.chars().take(400).collect(),
            });
        }

        let byte_stream = res
            .bytes_stream()
            .map(|chunk| chunk.map_err(UpstreamError::from));

        Ok(VllmSseStream { byte_stream, buffer: String::new() })
    }

    pub async fn complete_chat(&self, opts: VllmCompleteOptions) -> Result<String, UpstreamError> {
        let url = open_ai_chat_completions_url(&opts.base_url);
        let mut req = self.http.post(url).json(&build_vllm_chat_body(&VllmChatBodyOptions {
            model: &opts.model,
            messages: &opts.messages,
            stream: false,
            max_tokens: opts.max_tokens,
            frequency_penalty: opts.frequency_penalty,
            presence_penalty: opts.presence_penalty,
            temperature: opts.temperature,
            top_p: opts.top_p,
            enable_thinking: opts.enable_thinking,
        }));
        if let Some(key) = opts.api_key.as_deref().filter(|k| !k.is_empty()) {
            req = req.bearer_auth(key);
        }

        let res = req.send().await?;
        if !res.status().is_success() {
            let status = res.status().as_u16();
            let body = res.text().await.unwrap_or_default();
            return Err(UpstreamError::Http {
                status,
                body: body.chars().take(400).collect(),
            });
        }

        let data: Value = res.json().await?;
        let choices = data.get("choices").and_then(|c| c.as_array());
        let message = choices
            .and_then(|c| c.first())
            .and_then(|c| c.get("message"));
        Ok(message
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
            .unwrap_or_default()
            .trim()
            .to_string())
    }
}

struct VllmSseStream<S> {
    byte_stream: S,
    buffer: String,
}

impl<S> Stream for VllmSseStream<S>
where
    S: Stream<Item = Result<bytes::Bytes, UpstreamError>> + Unpin,
{
    type Item = Result<String, UpstreamError>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        loop {
            while let Some(newline_idx) = self.buffer.find('\n') {
                let line: String = self.buffer.drain(..=newline_idx).collect();
                let line = line.trim_end_matches('\n').trim_end_matches('\r').trim();
                if let Some(text) = process_sse_line(line)? {
                    return std::task::Poll::Ready(Some(Ok(text)));
                }
            }

            match Pin::new(&mut self.byte_stream).poll_next(cx) {
                std::task::Poll::Ready(Some(Ok(chunk))) => {
                    self.buffer.push_str(&String::from_utf8_lossy(&chunk));
                }
                std::task::Poll::Ready(Some(Err(e))) => {
                    return std::task::Poll::Ready(Some(Err(e)));
                }
                std::task::Poll::Ready(None) => {
                    if self.buffer.is_empty() {
                        return std::task::Poll::Ready(None);
                    }
                    let line = std::mem::take(&mut self.buffer);
                    if let Some(text) = process_sse_line(line.trim())? {
                        return std::task::Poll::Ready(Some(Ok(text)));
                    }
                    return std::task::Poll::Ready(None);
                }
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
    }
}

fn process_sse_line(line: &str) -> Result<Option<String>, UpstreamError> {
    let trimmed = line.trim();
    if !trimmed.starts_with("data:") {
        return Ok(None);
    }
    let data = trimmed.strip_prefix("data:").unwrap_or("").trim();
    if data == "[DONE]" {
        return Ok(None);
    }
    let chunk = match parse_sse_data_line(data)? {
        Some(v) => v,
        None => return Ok(None),
    };
    let choice = chunk.get("choices").and_then(|c| c.as_array()).and_then(|c| c.first());
    Ok(choice.and_then(stream_text_from_vllm_choice))
}

pub fn vllm_config_from_env(env: &HashMap<String, String>) -> Option<(String, Option<String>)> {
    let base_url = env
        .get("VLLM_BASE_URL")
        .or_else(|| env.get("TEECHAT_VLLM_BASE_URL"))
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())?
        .to_string();
    let api_key = env
        .get("VLLM_API_KEY")
        .or_else(|| env.get("TEECHAT_VLLM_API_KEY"))
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    Some((base_url, api_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_completions_url_normalizes_trailing_slash() {
        assert_eq!(
            open_ai_chat_completions_url("http://127.0.0.1:8000/"),
            "http://127.0.0.1:8000/v1/chat/completions"
        );
        assert_eq!(
            open_ai_chat_completions_url("http://127.0.0.1:8000/v1"),
            "http://127.0.0.1:8000/v1/chat/completions"
        );
    }
}
