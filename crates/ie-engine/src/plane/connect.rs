use std::sync::Arc;

use ie_protocol::{
    AttestedConnectRequest, AttestedConnectResponse, ENGINE_PLANE_PATH_CONNECT,
};
use ie_runtime::EngineClientTlsMaterial;

use super::challenge::normalize_gateway_connect_challenge_nonce;
use super::error::PlaneError;
use super::session::{AttestedH2Session, PlaneTransport};
use super::verify::GatewayAttestationVerifier;

#[derive(Clone)]
pub struct EnginePlaneDialOptions {
    pub gateway_base_url: String,
    pub tls: EngineClientTlsMaterial,
    pub reject_unauthorized: bool,
    pub connect_template: AttestedConnectRequest,
    pub pool_target_size: u32,
    pub gateway_challenge_nonce: Option<String>,
    pub gateway_verifier: Option<Arc<dyn GatewayAttestationVerifier>>,
}

/// Build the connect JSON body (TS `openPooledConnection` mutation).
pub fn build_connect_request(
    template: &AttestedConnectRequest,
    session_id: &str,
    pool_target_size: u32,
    gateway_challenge_nonce: Option<&str>,
) -> Result<AttestedConnectRequest, PlaneError> {
    let mut body = template.clone();
    body.session_id = session_id.to_string();
    body.pool_target_size = Some(pool_target_size);
    if let Some(raw) = gateway_challenge_nonce {
        let Some(norm) = normalize_gateway_connect_challenge_nonce(raw) else {
            return Err(PlaneError::GatewayChallengeNonceRequired);
        };
        body.gateway_challenge_nonce = Some(norm);
    }
    Ok(body)
}

/// Dial + POST `/v1/ope/control/connect` using an already-open transport (testable).
pub async fn open_pooled_connection_on_transport(
    transport: Box<dyn PlaneTransport>,
    opts: &EnginePlaneDialOptions,
    session_id: &str,
) -> Result<(AttestedH2Session, AttestedConnectResponse), PlaneError> {
    let body = build_connect_request(
        &opts.connect_template,
        session_id,
        opts.pool_target_size,
        opts.gateway_challenge_nonce.as_deref(),
    )?;

    let value = serde_json::to_value(&body)?;
    let resp = transport
        .request_json("POST", ENGINE_PLANE_PATH_CONNECT, Some(&value), &[])
        .await?;
    if resp.status != 200 {
        let _ = transport.close().await;
        return Err(PlaneError::ConnectHttp {
            status: resp.status,
            body: resp.json.to_string(),
        });
    }
    let parsed: AttestedConnectResponse = serde_json::from_value(resp.json.clone())?;

    if let Some(verifier) = &opts.gateway_verifier {
        let expected = body
            .gateway_challenge_nonce
            .as_deref()
            .ok_or(PlaneError::GatewayChallengeNonceRequired)?;
        if let Err(err) = verifier.verify_connect_response(&parsed, expected).await {
            let _ = transport.close().await;
            return Err(err);
        }
    }

    Ok((
        AttestedH2Session::from_transport(session_id.to_string(), transport),
        parsed,
    ))
}

/// Convenience: open a real hyper+TLS session and connect.
pub async fn open_pooled_connection(
    opts: &EnginePlaneDialOptions,
    session_id: &str,
) -> Result<(AttestedH2Session, AttestedConnectResponse), PlaneError> {
    let transport = super::hyper_transport::dial_hyper_transport(
        &opts.gateway_base_url,
        &opts.tls,
        opts.reject_unauthorized,
    )
    .await?;
    open_pooled_connection_on_transport(transport, opts, session_id).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use ie_protocol::{
        AttestationBundle, AttestationVerdict, CpuTeeAttestation, CpuTeeKind, EngineStartupIdentity,
        GpuTeeAttestation, GpuTeeKind, WorkloadMeasurements,
    };
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    use crate::plane::session::H2JsonResponse;

    fn sample_template() -> AttestedConnectRequest {
        AttestedConnectRequest {
            session_id: "old".into(),
            engine_id: "engine-1".into(),
            models: vec!["gemma".into()],
            identity: EngineStartupIdentity {
                engine_id: "engine-1".into(),
                kex: "kex".into(),
                ed25519_public: "pk".into(),
            },
            attestation: AttestationBundle {
                cpu_tee: CpuTeeAttestation {
                    kind: CpuTeeKind::SevSnp,
                    quote: "q".into(),
                    verdict: AttestationVerdict::Pass,
                    policy_id: "p".into(),
                },
                gpu_tee: GpuTeeAttestation {
                    kind: GpuTeeKind::NvCc,
                    evidence: "g".into(),
                    verdict: AttestationVerdict::Pass,
                },
                vllm: WorkloadMeasurements {
                    version: "v".into(),
                    binary_sha256: "b".repeat(64),
                },
                engine: WorkloadMeasurements {
                    version: "e".into(),
                    binary_sha256: "c".repeat(64),
                },
                ope: None,
                attested_mtls: None,
            },
            pool_target_size: None,
            instance_id: None,
            gateway_challenge_nonce: None,
        }
    }

    #[tokio::test]
    async fn connect_posts_expected_body() {
        let nonce = "AABBCCDDEEFF00112233445566778899";
        let tls = EngineClientTlsMaterial {
            ca_cert_pem: String::new(),
            client_cert_pem: String::new(),
            client_key_pem: String::new(),
            client_cert_sha256: "a".repeat(64),
        };
        let opts = EnginePlaneDialOptions {
            gateway_base_url: "https://gateway.example".into(),
            tls,
            reject_unauthorized: true,
            connect_template: sample_template(),
            pool_target_size: 2,
            gateway_challenge_nonce: Some(nonce.into()),
            gateway_verifier: None,
        };

        let seen = Arc::new(Mutex::new(None));
        struct Rec {
            status: u16,
            body: serde_json::Value,
            seen: Arc<Mutex<Option<(String, String, serde_json::Value)>>>,
        }
        #[async_trait]
        impl PlaneTransport for Rec {
            async fn request_json(
                &self,
                method: &str,
                path: &str,
                body: Option<&serde_json::Value>,
                _headers: &[(&str, &str)],
            ) -> Result<H2JsonResponse, PlaneError> {
                *self.seen.lock().unwrap() = Some((
                    method.into(),
                    path.into(),
                    body.cloned().unwrap_or(json!(null)),
                ));
                Ok(H2JsonResponse {
                    status: self.status,
                    json: self.body.clone(),
                })
            }
            async fn close(&self) -> Result<(), PlaneError> {
                Ok(())
            }
        }

        let transport = Box::new(Rec {
            status: 200,
            body: json!({ "ok": true, "pool_target_ack": 2 }),
            seen: seen.clone(),
        });
        let (_session, resp) = open_pooled_connection_on_transport(transport, &opts, "sess-9")
            .await
            .unwrap();
        assert!(resp.ok);
        let (method, path, body) = seen.lock().unwrap().clone().unwrap();
        assert_eq!(method, "POST");
        assert_eq!(path, ENGINE_PLANE_PATH_CONNECT);
        assert_eq!(body["session_id"], "sess-9");
        assert_eq!(body["pool_target_size"], 2);
        assert_eq!(
            body["gateway_challenge_nonce"],
            "aabbccddeeff00112233445566778899"
        );
    }

    #[tokio::test]
    async fn connect_non_200_is_connect_http() {
        let tls = EngineClientTlsMaterial {
            ca_cert_pem: String::new(),
            client_cert_pem: String::new(),
            client_key_pem: String::new(),
            client_cert_sha256: "a".repeat(64),
        };
        let opts = EnginePlaneDialOptions {
            gateway_base_url: "https://gateway.example".into(),
            tls,
            reject_unauthorized: true,
            connect_template: sample_template(),
            pool_target_size: 1,
            gateway_challenge_nonce: None,
            gateway_verifier: None,
        };
        struct FailTransport;
        #[async_trait]
        impl PlaneTransport for FailTransport {
            async fn request_json(
                &self,
                _method: &str,
                _path: &str,
                _body: Option<&serde_json::Value>,
                _headers: &[(&str, &str)],
            ) -> Result<H2JsonResponse, PlaneError> {
                Ok(H2JsonResponse {
                    status: 503,
                    json: json!({ "error": "busy" }),
                })
            }
            async fn close(&self) -> Result<(), PlaneError> {
                Ok(())
            }
        }
        let err = match open_pooled_connection_on_transport(Box::new(FailTransport), &opts, "s").await
        {
            Ok(_) => panic!("expected connect failure"),
            Err(e) => e,
        };
        match err {
            PlaneError::ConnectHttp { status, body } => {
                assert_eq!(status, 503);
                assert!(body.contains("busy"));
            }
            other => panic!("unexpected {other}"),
        }
    }
}
