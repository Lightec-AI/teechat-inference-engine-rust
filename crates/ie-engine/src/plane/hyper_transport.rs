//! Real HTTP/2 + rustls dialer for the engine plane.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use http_body::Frame;
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use ie_runtime::EngineClientTlsMaterial;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use serde_json::Value;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio_rustls::TlsConnector;
use url::Url;

use super::error::PlaneError;
use super::session::{H2BytesResponse, H2JsonResponse, PlaneTransport, StreamingPostHandle};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type ReqBody = BoxBody<Bytes, BoxError>;
type SendRequest = hyper::client::conn::http2::SendRequest<ReqBody>;

fn full_bytes(payload: Bytes) -> ReqBody {
    Full::new(payload)
        .map_err(|e: std::convert::Infallible| match e {})
        .boxed()
}

pub struct HyperPlaneTransport {
    sender: Mutex<SendRequest>,
    authority: String,
    closed: Arc<AtomicBool>,
}

impl HyperPlaneTransport {
    fn mark_closed(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }
}

impl HyperPlaneTransport {
    async fn send(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
        headers: &[(&str, &str)],
    ) -> Result<H2JsonResponse, PlaneError> {
        let payload = match body {
            Some(v) => Bytes::from(serde_json::to_vec(v)?),
            None => Bytes::new(),
        };
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header(http::header::HOST, self.authority.as_str());
        if body.is_some() {
            builder = builder.header(http::header::CONTENT_TYPE, "application/json");
        }
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        let req = builder
            .body(full_bytes(payload))
            .map_err(|e| PlaneError::H2(e.to_string()))?;

        // Release SendRequest before awaiting the body so long-poll work-pull and
        // concurrent ephemeral POSTs can multiplex on the same H2 connection.
        let response = {
            let mut sender = self.sender.lock().await;
            if sender.is_closed() {
                self.mark_closed();
                return Err(PlaneError::H2("h2 connection closed".into()));
            }
            match sender.send_request(req).await {
                Ok(r) => r,
                Err(e) => {
                    self.mark_closed();
                    return Err(PlaneError::H2(format!("send_request: {e:?}")));
                }
            }
        };
        let status = response.status().as_u16();
        let collected = response
            .into_body()
            .collect()
            .await
            .map_err(|e| {
                self.mark_closed();
                PlaneError::H2(format!("body: {e:?}"))
            })?;
        let bytes = collected.to_bytes();
        let json = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::String(
                String::from_utf8_lossy(&bytes).into_owned(),
            ))
        };
        Ok(H2JsonResponse { status, json })
    }

    async fn send_bytes(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
        content_type: Option<&str>,
        headers: &[(&str, &str)],
    ) -> Result<H2BytesResponse, PlaneError> {
        let payload = Bytes::from(body.unwrap_or_default().to_vec());
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header(http::header::HOST, self.authority.as_str());
        if let Some(ct) = content_type {
            builder = builder.header(http::header::CONTENT_TYPE, ct);
        } else if body.is_some() {
            builder = builder.header(http::header::CONTENT_TYPE, "application/json");
        }
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        let req = builder
            .body(full_bytes(payload))
            .map_err(|e| PlaneError::H2(e.to_string()))?;

        let response = {
            let mut sender = self.sender.lock().await;
            if sender.is_closed() {
                self.mark_closed();
                return Err(PlaneError::H2("h2 connection closed".into()));
            }
            match sender.send_request(req).await {
                Ok(r) => r,
                Err(e) => {
                    self.mark_closed();
                    return Err(PlaneError::H2(format!("send_request: {e:?}")));
                }
            }
        };
        let status = response.status().as_u16();
        let mut headers_out = Vec::new();
        for (name, value) in response.headers().iter() {
            if let Ok(v) = value.to_str() {
                headers_out.push((name.as_str().to_string(), v.to_string()));
            }
        }
        let collected = response
            .into_body()
            .collect()
            .await
            .map_err(|e| {
                self.mark_closed();
                PlaneError::H2(format!("body: {e:?}"))
            })?;
        Ok(H2BytesResponse {
            status,
            headers: headers_out,
            body: collected.to_bytes(),
        })
    }

    async fn open_streaming_post(
        &self,
        path: &str,
        content_type: &str,
        headers: &[(&str, &str)],
    ) -> Result<StreamingPostHandle, PlaneError> {
        let (tx, rx) = mpsc::unbounded_channel::<Bytes>();
        let body_stream = stream::unfold(rx, |mut rx| async move {
            rx.recv()
                .await
                .map(|bytes| (Ok::<_, BoxError>(Frame::data(bytes)), rx))
        });
        let body = StreamBody::new(body_stream).boxed();

        let mut builder = Request::builder()
            .method("POST")
            .uri(path)
            .header(http::header::HOST, self.authority.as_str())
            .header(http::header::CONTENT_TYPE, content_type);
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        let req = builder
            .body(body)
            .map_err(|e| PlaneError::H2(e.to_string()))?;

        let response_fut = {
            let mut sender = self.sender.lock().await;
            // Do not await here: polling the future drives the streaming request body.
            sender.send_request(req)
        };

        let join = tokio::spawn(async move {
            let response = response_fut
                .await
                .map_err(|e| PlaneError::H2(format!("response: {e:?}")))?;
            let status = response.status().as_u16();
            let mut headers_out = Vec::new();
            for (name, value) in response.headers().iter() {
                if let Ok(v) = value.to_str() {
                    headers_out.push((name.as_str().to_string(), v.to_string()));
                }
            }
            let collected = response
                .into_body()
                .collect()
                .await
                .map_err(|e| PlaneError::H2(format!("body: {e:?}")))?;
            Ok(H2BytesResponse {
                status,
                headers: headers_out,
                body: collected.to_bytes(),
            })
        });

        Ok(StreamingPostHandle::new(tx, join))
    }
}

#[async_trait]
impl PlaneTransport for HyperPlaneTransport {
    fn is_closed(&self) -> bool {
        if self.closed.load(Ordering::SeqCst) {
            return true;
        }
        self.sender
            .try_lock()
            .map(|s| s.is_closed())
            .unwrap_or(false)
    }

    async fn request_json(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
        headers: &[(&str, &str)],
    ) -> Result<H2JsonResponse, PlaneError> {
        self.send(method, path, body, headers).await
    }

    async fn request_bytes(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
        content_type: Option<&str>,
        headers: &[(&str, &str)],
    ) -> Result<H2BytesResponse, PlaneError> {
        self.send_bytes(method, path, body, content_type, headers)
            .await
    }

    async fn open_streaming_bytes_post(
        &self,
        path: &str,
        content_type: &str,
        headers: &[(&str, &str)],
    ) -> Result<StreamingPostHandle, PlaneError> {
        self.open_streaming_post(path, content_type, headers).await
    }

    async fn close(&self) -> Result<(), PlaneError> {
        self.mark_closed();
        Ok(())
    }
}

pub async fn dial_hyper_transport(
    gateway_base_url: &str,
    tls: &EngineClientTlsMaterial,
    reject_unauthorized: bool,
) -> Result<Box<dyn PlaneTransport>, PlaneError> {
    let url = Url::parse(gateway_base_url).map_err(|e| PlaneError::InvalidUrl(e.to_string()))?;
    let host = url
        .host_str()
        .ok_or_else(|| PlaneError::InvalidUrl("missing host".into()))?
        .to_string();
    let port = url.port_or_known_default().unwrap_or(443);
    let server_name = ServerName::try_from(host.clone())
        .map_err(|e| PlaneError::Tls(format!("invalid SNI: {e}")))?;

    let client_config = build_client_config(tls, reject_unauthorized)?;
    let connector = TlsConnector::from(Arc::new(client_config));

    let tcp = TcpStream::connect((host.as_str(), port))
        .await
        .map_err(PlaneError::Io)?;
    let tls_stream = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| PlaneError::Tls(format!("{e:?}")))?;
    let alpn = tls_stream
        .get_ref()
        .1
        .alpn_protocol()
        .map(|p| String::from_utf8_lossy(p).into_owned());
    if alpn.as_deref() != Some("h2") {
        return Err(PlaneError::Tls(format!(
            "expected ALPN h2, negotiated={alpn:?}"
        )));
    }

    let io = TokioIo::new(tls_stream);
    let (sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake(io)
        .await
        .map_err(|e| PlaneError::H2(format!("{e:?}")))?;

    let closed = Arc::new(AtomicBool::new(false));
    let closed_watch = Arc::clone(&closed);
    tokio::spawn(async move {
        if let Err(err) = conn.await {
            tracing::warn!(error = %err, "engine-plane h2 connection closed");
        }
        closed_watch.store(true, Ordering::SeqCst);
    });

    let authority = if port == 443 {
        host
    } else {
        format!("{host}:{port}")
    };
    Ok(Box::new(HyperPlaneTransport {
        sender: Mutex::new(sender),
        authority,
        closed,
    }))
}

fn build_client_config(
    tls: &EngineClientTlsMaterial,
    reject_unauthorized: bool,
) -> Result<ClientConfig, PlaneError> {
    let mut root_store = RootCertStore::empty();
    let mut ca_reader = std::io::Cursor::new(tls.ca_cert_pem.as_bytes());
    for cert in rustls_pemfile::certs(&mut ca_reader) {
        let cert = cert.map_err(|e| PlaneError::Tls(format!("ca pem: {e}")))?;
        root_store
            .add(cert)
            .map_err(|e| PlaneError::Tls(format!("ca add: {e}")))?;
    }

    let mut cert_reader = std::io::Cursor::new(tls.client_cert_pem.as_bytes());
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<_, _>>()
        .map_err(|e| PlaneError::Tls(format!("client cert: {e}")))?;

    let mut key_reader = std::io::Cursor::new(tls.client_key_pem.as_bytes());
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| PlaneError::Tls(format!("client key: {e}")))?
        .ok_or_else(|| PlaneError::Tls("client key missing".into()))?;

    let builder = ClientConfig::builder().with_root_certificates(root_store);
    let mut config = builder
        .with_client_auth_cert(certs, key)
        .map_err(|e| PlaneError::Tls(format!("client auth: {e}")))?;
    config.alpn_protocols = vec![b"h2".to_vec()];

    if !reject_unauthorized {
        return Err(PlaneError::Tls(
            "reject_unauthorized=false is disabled; set TEECHAT_ENGINE_ALLOW_INSECURE_TLS=1 only for local labs".into(),
        ));
    }

    let _ = reject_unauthorized;
    Ok(config)
}
