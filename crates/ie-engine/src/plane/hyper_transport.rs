//! Real HTTP/2 + rustls dialer for the engine plane.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use ie_runtime::EngineClientTlsMaterial;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use serde_json::Value;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;
use url::Url;

use super::error::PlaneError;
use super::session::{H2JsonResponse, PlaneTransport};

type SendRequest = hyper::client::conn::http2::SendRequest<Full<Bytes>>;

pub struct HyperPlaneTransport {
    sender: Mutex<SendRequest>,
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
        let mut builder = Request::builder().method(method).uri(path);
        if body.is_some() {
            builder = builder.header(http::header::CONTENT_TYPE, "application/json");
        }
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        let req = builder
            .body(Full::new(payload))
            .map_err(|e| PlaneError::H2(e.to_string()))?;

        let mut sender = self.sender.lock().await;
        let response = sender
            .send_request(req)
            .await
            .map_err(|e| PlaneError::H2(e.to_string()))?;
        let status = response.status().as_u16();
        let collected = response
            .into_body()
            .collect()
            .await
            .map_err(|e| PlaneError::H2(e.to_string()))?;
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
}

#[async_trait]
impl PlaneTransport for HyperPlaneTransport {
    async fn request_json(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
        headers: &[(&str, &str)],
    ) -> Result<H2JsonResponse, PlaneError> {
        self.send(method, path, body, headers).await
    }

    async fn close(self: Box<Self>) -> Result<(), PlaneError> {
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
        .map_err(|e| PlaneError::Tls(e.to_string()))?;

    let io = TokioIo::new(tls_stream);
    let (sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake(io)
        .await
        .map_err(|e| PlaneError::H2(e.to_string()))?;

    tokio::spawn(async move {
        if let Err(err) = conn.await {
            tracing::warn!(error = %err, "engine-plane h2 connection closed");
        }
    });

    Ok(Box::new(HyperPlaneTransport {
        sender: Mutex::new(sender),
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
        .with_client_auth_cert(certs, PrivateKeyDer::from(key))
        .map_err(|e| PlaneError::Tls(format!("client auth: {e}")))?;
    config.alpn_protocols = vec![b"h2".to_vec()];

    if !reject_unauthorized {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoVerifier));
    }

    Ok(config)
}

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
