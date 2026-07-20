//! OPE §7 streaming frames (NDJSON).
//!
//! Port of `src/protocol/ope-stream.ts`.

use serde::{Deserialize, Serialize};

pub const CONTENT_TYPE_OPE_JSON_STREAM: &str = "application/ope+json-stream";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpeStreamStatusPhase {
    Mode,
    SearchQuery,
    FetchPage,
    ProcessPages,
    Thinking,
    Streaming,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OpeStreamFrame {
    ServerShare {
        ope_stream: String,
        server_share: String,
    },
    Ciphertext {
        ope_stream: String,
        seq: u32,
        ciphertext: String,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        final_: bool,
    },
    Trailer {
        ope_stream: String,
        #[serde(rename = "type")]
        frame_type: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        usage_report: Option<String>,
    },
    Status {
        ope_stream: String,
        #[serde(rename = "type")]
        frame_type: String,
        phase: OpeStreamStatusPhase,
        #[serde(skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        mode: Option<String>,
    },
}

impl OpeStreamFrame {
    pub const VERSION: &'static str = "1.0";

    pub fn server_share(share: impl Into<String>) -> Self {
        Self::ServerShare {
            ope_stream: Self::VERSION.into(),
            server_share: share.into(),
        }
    }

    pub fn ciphertext(seq: u32, ciphertext: impl Into<String>, final_: bool) -> Self {
        Self::Ciphertext {
            ope_stream: Self::VERSION.into(),
            seq,
            ciphertext: ciphertext.into(),
            final_,
        }
    }

    pub fn trailer(usage_report: Option<String>) -> Self {
        Self::Trailer {
            ope_stream: Self::VERSION.into(),
            frame_type: "trailer".into(),
            usage_report,
        }
    }

    pub fn status(
        phase: OpeStreamStatusPhase,
        detail: Option<String>,
        mode: Option<String>,
    ) -> Self {
        Self::Status {
            ope_stream: Self::VERSION.into(),
            frame_type: "status".into(),
            phase,
            detail,
            mode,
        }
    }
}

/// Serialize an OPE stream frame as a single NDJSON line (including trailing newline).
pub fn encode_ope_stream_line(frame: &OpeStreamFrame) -> Result<Vec<u8>, serde_json::Error> {
    // `final` is a Rust keyword; emit wire key via Value reshape for ciphertext frames.
    let mut value = serde_json::to_value(frame)?;
    if let Some(obj) = value.as_object_mut() {
        if let Some(final_flag) = obj.remove("final_") {
            if final_flag.as_bool() == Some(true) {
                obj.insert("final".into(), final_flag);
            }
        }
    }
    let mut line = serde_json::to_vec(&value)?;
    line.push(b'\n');
    Ok(line)
}

pub fn encode_ope_status_line(
    phase: OpeStreamStatusPhase,
    detail: Option<&str>,
    mode: Option<&str>,
) -> Result<Vec<u8>, serde_json::Error> {
    encode_ope_stream_line(&OpeStreamFrame::status(
        phase,
        detail.map(str::to_string),
        mode.map(str::to_string),
    ))
}

/// Parse one NDJSON line into an OPE stream frame. Empty/invalid lines return `None`.
pub fn parse_ope_stream_line(line: &str) -> Option<OpeStreamFrame> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let j: serde_json::Value = serde_json::from_str(trimmed).ok()?;
    let obj = j.as_object()?;
    if obj.get("ope_stream").and_then(|v| v.as_str()) != Some("1.0") {
        return None;
    }
    if obj.get("type").and_then(|v| v.as_str()) == Some("trailer") {
        return Some(OpeStreamFrame::trailer(
            obj.get("usage_report")
                .and_then(|v| v.as_str())
                .map(str::to_string),
        ));
    }
    if obj.get("type").and_then(|v| v.as_str()) == Some("status") {
        let phase_str = obj.get("phase").and_then(|v| v.as_str())?;
        let phase: OpeStreamStatusPhase = serde_json::from_value(serde_json::Value::String(
            phase_str.to_string(),
        ))
        .ok()?;
        return Some(OpeStreamFrame::status(
            phase,
            obj.get("detail")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            obj.get("mode").and_then(|v| v.as_str()).map(str::to_string),
        ));
    }
    if let Some(share) = obj.get("server_share").and_then(|v| v.as_str()) {
        return Some(OpeStreamFrame::server_share(share));
    }
    if let (Some(seq), Some(ct)) = (
        obj.get("seq").and_then(|v| v.as_u64()),
        obj.get("ciphertext").and_then(|v| v.as_str()),
    ) {
        return Some(OpeStreamFrame::ciphertext(
            seq as u32,
            ct,
            obj.get("final").and_then(|v| v.as_bool()) == Some(true),
        ));
    }
    None
}

pub fn is_ope_stream_content_type(content_type: Option<&str>) -> bool {
    content_type
        .unwrap_or("")
        .contains(CONTENT_TYPE_OPE_JSON_STREAM)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_parse_ciphertext_final() {
        let frame = OpeStreamFrame::ciphertext(3, "abc", true);
        let line = String::from_utf8(encode_ope_stream_line(&frame).unwrap()).unwrap();
        assert!(line.contains("\"final\":true"));
        assert!(!line.contains("final_"));
        let parsed = parse_ope_stream_line(&line).unwrap();
        match parsed {
            OpeStreamFrame::Ciphertext {
                seq,
                ciphertext,
                final_,
                ..
            } => {
                assert_eq!(seq, 3);
                assert_eq!(ciphertext, "abc");
                assert!(final_);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parse_status_and_trailer() {
        let status = r#"{"ope_stream":"1.0","type":"status","phase":"thinking","detail":"x"}"#;
        let parsed = parse_ope_stream_line(status).unwrap();
        match parsed {
            OpeStreamFrame::Status { phase, detail, .. } => {
                assert_eq!(phase, OpeStreamStatusPhase::Thinking);
                assert_eq!(detail.as_deref(), Some("x"));
            }
            other => panic!("unexpected {other:?}"),
        }
        let trailer = r#"{"ope_stream":"1.0","type":"trailer","usage_report":"rep"}"#;
        match parse_ope_stream_line(trailer).unwrap() {
            OpeStreamFrame::Trailer { usage_report, .. } => {
                assert_eq!(usage_report.as_deref(), Some("rep"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn content_type_helper() {
        assert!(is_ope_stream_content_type(Some(
            "application/ope+json-stream; charset=utf-8"
        )));
        assert!(!is_ope_stream_content_type(Some("application/json")));
    }
}
