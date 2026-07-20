//! Mock H2 gateway + mock vLLM → Rust decrypt → encrypt → result (M2 integration).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use ie_crypto::{
    client_encrypt_request, test_mock_engine, test_sender_keypair, CryptoProvider,
    RealCryptoProvider,
};
use ie_engine::{
    start_pull_worker, H2BytesResponse, H2JsonResponse, OpeInferenceOptions, PlaneError,
    PlaneTransport,
};
use ie_protocol::{
    OpeEnvelope, OpeEnvelopeMeta, CONTENT_TYPE_OPE_JSON_STREAM, ENGINE_PLANE_PATH_INFERENCE_RESULT,
    ENGINE_PLANE_PATH_WORK_PULL, HEADER_OPE_REQUEST_ID, HEADER_OPE_SESSION_ID,
    HEADER_OPE_TRAFFIC_CLASS, OPE_TRAFFIC_CLASS_LIVE_CHAT,
};
use ie_upstream::VllmChatClient;
use ope_e2e::ClientSession;
use ope_envelope::{sign_envelope, Envelope};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

type ResultRecord = (Vec<(String, String)>, Bytes);

struct MockGateway {
    pulls: Mutex<VecDeque<H2BytesResponse>>,
    results: Arc<Mutex<Vec<ResultRecord>>>,
}

#[async_trait]
impl PlaneTransport for MockGateway {
    async fn request_json(
        &self,
        method: &str,
        path: &str,
        body: Option<&serde_json::Value>,
        headers: &[(&str, &str)],
    ) -> Result<H2JsonResponse, PlaneError> {
        let raw = self
            .request_bytes(
                method,
                path,
                body.map(|v| serde_json::to_vec(v).unwrap()).as_deref(),
                Some("application/json"),
                headers,
            )
            .await?;
        let json = if raw.body.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&raw.body).unwrap_or(serde_json::Value::Null)
        };
        Ok(H2JsonResponse {
            status: raw.status,
            json,
        })
    }

    async fn request_bytes(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
        _content_type: Option<&str>,
        headers: &[(&str, &str)],
    ) -> Result<H2BytesResponse, PlaneError> {
        if method == "GET" && path == ENGINE_PLANE_PATH_WORK_PULL {
            let next = self.pulls.lock().unwrap().pop_front();
            return Ok(next.unwrap_or(H2BytesResponse {
                status: 204,
                headers: vec![],
                body: Bytes::new(),
            }));
        }
        if method == "POST" && path == ENGINE_PLANE_PATH_INFERENCE_RESULT {
            let hdrs = headers
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect();
            self.results
                .lock()
                .unwrap()
                .push((hdrs, Bytes::from(body.unwrap_or_default().to_vec())));
            return Ok(H2BytesResponse {
                status: 200,
                headers: vec![],
                body: Bytes::from_static(b"{\"ok\":true}"),
            });
        }
        Err(PlaneError::H2(format!("unexpected {method} {path}")))
    }

    async fn open_streaming_bytes_post(
        &self,
        path: &str,
        _content_type: &str,
        headers: &[(&str, &str)],
    ) -> Result<ie_engine::StreamingPostHandle, PlaneError> {
        use tokio::sync::mpsc;
        let (tx, mut rx) = mpsc::unbounded_channel::<Bytes>();
        let store = Arc::clone(&self.results);
        let hdrs: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        let path = path.to_string();
        let join = tokio::spawn(async move {
            let mut buf = Vec::new();
            while let Some(chunk) = rx.recv().await {
                buf.extend_from_slice(&chunk);
            }
            if path == ENGINE_PLANE_PATH_INFERENCE_RESULT {
                store.lock().unwrap().push((hdrs, Bytes::from(buf)));
            }
            Ok(H2BytesResponse {
                status: 200,
                headers: vec![],
                body: Bytes::from_static(b"{\"ok\":true}"),
            })
        });
        Ok(ie_engine::StreamingPostHandle::new(tx, join))
    }

    async fn close(&self) -> Result<(), PlaneError> {
        Ok(())
    }
}

#[tokio::test]
async fn mock_gateway_assign_work_decrypt_vllm_encrypt_result() {
    let vllm = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "data: {\"choices\":[{\"delta\":{\"content\":\"hello \"}}]}\n\n\
             data: {\"choices\":[{\"delta\":{\"content\":\"world\"}}]}\n\n\
             data: [DONE]\n\n",
        ))
        .mount(&vllm)
        .await;

    let (secret, engine_pub) = test_mock_engine();
    let provider = Arc::new(RealCryptoProvider::new());
    let handle = provider.register_secret(secret).unwrap();
    let client_session = ClientSession::generate().unwrap();
    let sender = test_sender_keypair();

    let payload = json!({
        "model": "test-model",
        "messages": [{"role": "user", "content": "secret prompt"}]
    });
    let base = Envelope {
        ope_version: Envelope::VERSION.into(),
        alg: Envelope::ALG_EDDSA.into(),
        enc: Envelope::ENC_NONE.into(),
        kid: "sender-dev".into(),
        recipient: "gateway-dev".into(),
        engine_id: None,
        ts: "2026-05-19T12:00:00Z".into(),
        nonce: "bm9uY2VfZGV2X2UxZQ".into(),
        payload_hash: String::new(),
        payload: None,
        ciphertext: None,
        iv: None,
        aad: None,
        meta: Some(json!({
            "model": "test-model",
            "conversation_id": "conv-1",
            "traffic_class": OPE_TRAFFIC_CLASS_LIVE_CHAT,
        })),
        e2e: None,
        sig: None,
    };
    let mut protocol_env =
        client_encrypt_request(&engine_pub, &payload, base, Some(&client_session)).unwrap();
    {
        let mut ope = ie_crypto::protocol_to_ope_envelope(&protocol_env).unwrap();
        sign_envelope(&mut ope, &sender.secret).unwrap();
        protocol_env = ie_crypto::ope_to_protocol_envelope(&ope).unwrap();
    }
    // Ensure gate fields present.
    if let Some(ref mut e2e) = protocol_env.e2e {
        if e2e.ephemeral_epoch.is_empty() {
            e2e.ephemeral_epoch = "epoch-test".into();
        }
    }
    protocol_env.meta = Some(OpeEnvelopeMeta {
        conversation_id: Some("conv-1".into()),
        model: Some("test-model".into()),
        tenant: None,
        metering: None,
        route: None,
        traffic_class: Some(OPE_TRAFFIC_CLASS_LIVE_CHAT.into()),
        gateway_task: None,
    });

    let envelope_bytes = serde_json::to_vec(&protocol_env).unwrap();
    let gateway = Arc::new(MockGateway {
        pulls: Mutex::new(VecDeque::from([H2BytesResponse {
            status: 200,
            headers: vec![
                (HEADER_OPE_REQUEST_ID.into(), "req-1".into()),
                (HEADER_OPE_TRAFFIC_CLASS.into(), OPE_TRAFFIC_CLASS_LIVE_CHAT.into()),
                (HEADER_OPE_SESSION_ID.into(), "sess-1".into()),
            ],
            body: Bytes::from(envelope_bytes),
        }])),
        results: Arc::new(Mutex::new(Vec::new())),
    });

    let inference = OpeInferenceOptions {
        request_id: None,
        decrypt_handle: handle,
        rotating: None,
        provider: provider.clone() as Arc<dyn CryptoProvider>,
        vllm_base_url: vllm.uri(),
        vllm_api_key: None,
        vllm: VllmChatClient::default(),
        chunk_chars: 8,
        kv: None,
        usage_signing_key: None,
    };

    let worker = start_pull_worker(gateway.clone(), "sess-1".into(), inference);

    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(5);
    loop {
        if !gateway.results.lock().unwrap().is_empty() {
            break;
        }
        if tokio::time::Instant::now() > deadline {
            worker.stop();
            panic!("timed out waiting for inference result");
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
    }
    worker.stop();
    worker.join().await;

    let results = gateway.results.lock().unwrap();
    assert_eq!(results.len(), 1);
    let (hdrs, body) = &results[0];
    assert!(hdrs
        .iter()
        .any(|(k, v)| k == HEADER_OPE_REQUEST_ID && v == "req-1"));
    let body_str = String::from_utf8_lossy(body);
    assert!(
        body_str.contains("server_share") || body_str.contains(CONTENT_TYPE_OPE_JSON_STREAM) || body_str.contains("ope_stream"),
        "expected OPE stream frames, got: {body_str}"
    );
    assert!(body_str.contains("ope_stream") || body_str.contains("ciphertext"));
    let _ = protocol_env; // keep type linked
    let _: OpeEnvelope = protocol_env;
}
