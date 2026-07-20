use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use serde::Serialize;
use serde_json::Value;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::error::PlaneError;

#[derive(Debug, Clone)]
pub struct H2JsonResponse {
    pub status: u16,
    pub json: Value,
}

#[derive(Debug, Clone)]
pub struct H2BytesResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

impl H2BytesResponse {
    pub fn header_value(&self, name: &str) -> Option<&str> {
        let want = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(&want))
            .map(|(_, v)| v.as_str())
    }
}

/// Incremental POST body (engine → gateway `/v1/ope/inference/result` NDJSON).
pub struct StreamingPostHandle {
    tx: Option<mpsc::UnboundedSender<Bytes>>,
    join: JoinHandle<Result<H2BytesResponse, PlaneError>>,
}

impl StreamingPostHandle {
    pub fn new(
        tx: mpsc::UnboundedSender<Bytes>,
        join: JoinHandle<Result<H2BytesResponse, PlaneError>>,
    ) -> Self {
        Self {
            tx: Some(tx),
            join,
        }
    }

    pub fn write(&mut self, chunk: &[u8]) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(Bytes::copy_from_slice(chunk));
        }
    }

    pub async fn finish(mut self) -> Result<H2BytesResponse, PlaneError> {
        drop(self.tx.take());
        self.join
            .await
            .map_err(|e| PlaneError::H2(format!("streaming post join: {e}")))?
    }

    pub fn abort(mut self) {
        drop(self.tx.take());
        self.join.abort();
    }
}

/// Abstract long-lived engine-plane session transport (one HTTP/2 connection).
#[async_trait]
pub trait PlaneTransport: Send + Sync {
    async fn request_json(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
        headers: &[(&str, &str)],
    ) -> Result<H2JsonResponse, PlaneError>;

    /// Raw request (used for work-pull GET and inference/result POST).
    ///
    /// Default: JSON round-trip via [`Self::request_json`] (no response headers).
    async fn request_bytes(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
        content_type: Option<&str>,
        headers: &[(&str, &str)],
    ) -> Result<H2BytesResponse, PlaneError> {
        let mut hdrs: Vec<(&str, &str)> = headers.to_vec();
        if let Some(ct) = content_type {
            hdrs.push(("content-type", ct));
        }
        let value = match body {
            Some(b) if !b.is_empty() => Some(serde_json::from_slice(b).unwrap_or(Value::Null)),
            _ => None,
        };
        let r = self
            .request_json(method, path, value.as_ref(), &hdrs)
            .await?;
        let body = if r.json.is_null() {
            Bytes::new()
        } else {
            Bytes::from(serde_json::to_vec(&r.json).unwrap_or_default())
        };
        Ok(H2BytesResponse {
            status: r.status,
            headers: Vec::new(),
            body,
        })
    }

    /// Open a streaming POST (headers first). Write NDJSON via the handle, then [`StreamingPostHandle::finish`].
    ///
    /// Default falls back to buffering (tests / stubs).
    async fn open_streaming_bytes_post(
        &self,
        path: &str,
        content_type: &str,
        headers: &[(&str, &str)],
    ) -> Result<StreamingPostHandle, PlaneError> {
        let (tx, mut rx) = mpsc::unbounded_channel::<Bytes>();
        let path = path.to_string();
        let content_type = content_type.to_string();
        let headers_owned: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        // Can't move `self` into task — buffer then POST in finish-compatible join.
        // Callers that need real streaming must override (HyperPlaneTransport).
        let this_headers = headers_owned.clone();
        let join = tokio::spawn(async move {
            let mut buf = Vec::new();
            while let Some(chunk) = rx.recv().await {
                buf.extend_from_slice(&chunk);
            }
            let _ = (path, content_type, this_headers, buf);
            Err(PlaneError::H2(
                "open_streaming_bytes_post default stub — override on real transport".into(),
            ))
        });
        Ok(StreamingPostHandle::new(tx, join))
    }

    async fn close(&self) -> Result<(), PlaneError>;
}

/// Live attested session owning the transport.
pub struct AttestedH2Session {
    session_id: String,
    transport: Arc<dyn PlaneTransport>,
}

impl AttestedH2Session {
    pub fn from_transport(session_id: String, transport: Box<dyn PlaneTransport>) -> Self {
        Self {
            session_id,
            transport: Arc::from(transport),
        }
    }

    pub fn from_arc(session_id: String, transport: Arc<dyn PlaneTransport>) -> Self {
        Self {
            session_id,
            transport,
        }
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn transport(&self) -> Arc<dyn PlaneTransport> {
        self.transport.clone()
    }

    pub async fn request_json(
        &self,
        method: &str,
        path: &str,
        body: Option<&impl Serialize>,
        headers: &[(&str, &str)],
    ) -> Result<H2JsonResponse, PlaneError> {
        let value = match body {
            Some(b) => Some(serde_json::to_value(b)?),
            None => None,
        };
        self.transport
            .request_json(method, path, value.as_ref(), headers)
            .await
    }

    pub async fn request_bytes(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
        content_type: Option<&str>,
        headers: &[(&str, &str)],
    ) -> Result<H2BytesResponse, PlaneError> {
        self.transport
            .request_bytes(method, path, body, content_type, headers)
            .await
    }

    pub async fn close(self) -> Result<(), PlaneError> {
        self.transport.close().await
    }
}
