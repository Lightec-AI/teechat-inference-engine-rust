//! Work-pull loop (port of `startPullWorker` in `engine-plane/pool-client.ts`).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::{future::Future, pin::Pin};

use ie_protocol::{
    traffic_class_header_meta_consistent, EngineOpsControlRequest, EngineOpsControlResult,
    OpeEnvelope, TrafficClassConsistency, CONTENT_TYPE_OPE_JSON, CONTENT_TYPE_OPE_JSON_STREAM,
    ENGINE_PLANE_PATH_CHALLENGE_RESULT, ENGINE_PLANE_PATH_INFERENCE_RESULT,
    ENGINE_PLANE_PATH_OPS_CONTROL_RESULT, ENGINE_PLANE_PATH_WORK_PULL, HEADER_OPE_REQUEST_ID,
    HEADER_OPE_SESSION_ID, HEADER_OPE_TRAFFIC_CLASS, HEADER_OPE_WORK_KIND, HEADER_USAGE_REPORT,
    OPE_WORK_KIND_CHALLENGE, OPE_WORK_KIND_OPS_CONTROL,
};
use tokio::sync::Notify;
use tracing::{info, warn};

use crate::desired_pool::{
    parse_desired_pool_target_header, DesiredPoolTargetCallback, HEADER_OPE_DESIRED_POOL_TARGET,
};
use crate::infer::{
    is_gateway_plane_task_envelope, run_ope_inference_on_envelope, validate_ope_inference_envelope,
    GateResult, NdjsonStreamWriter, OpeInferenceOptions,
};
use ie_upstream::VllmChatClient;

use super::error::PlaneError;
use super::session::{PlaneTransport, StreamingPostHandle};

pub type EngineChallengeHandlerFuture = Pin<
    Box<dyn Future<Output = Result<crate::EngineChallengeWireResponse, String>> + Send + 'static>,
>;
pub type EngineChallengeHandler =
    Arc<dyn Fn(crate::EngineChallengeWireRequest) -> EngineChallengeHandlerFuture + Send + Sync>;

pub type EngineOpsControlHandlerFuture =
    Pin<Box<dyn Future<Output = EngineOpsControlResult> + Send + 'static>>;
pub type EngineOpsControlHandler =
    Arc<dyn Fn(EngineOpsControlRequest) -> EngineOpsControlHandlerFuture + Send + Sync>;

pub struct PullWorkerHandle {
    stop: Arc<AtomicBool>,
    busy: Arc<AtomicBool>,
    notify: Arc<Notify>,
    join: tokio::task::JoinHandle<()>,
}

impl PullWorkerHandle {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    pub fn is_busy(&self) -> bool {
        self.busy.load(Ordering::SeqCst)
    }

    pub async fn join(self) {
        self.stop();
        let _ = self.join.await;
    }
}

/// Start a background pull worker on an attested H2 transport.
pub fn start_pull_worker(
    transport: Arc<dyn PlaneTransport>,
    session_id: String,
    inference: OpeInferenceOptions,
    on_desired_pool_target: Option<DesiredPoolTargetCallback>,
    answer_challenge: Option<EngineChallengeHandler>,
    answer_ops_control: Option<EngineOpsControlHandler>,
    on_transport_lost: Option<crate::pull_workers::TransportLostFn>,
) -> PullWorkerHandle {
    let stop = Arc::new(AtomicBool::new(false));
    let busy = Arc::new(AtomicBool::new(false));
    let notify = Arc::new(Notify::new());
    let stop_c = stop.clone();
    let busy_c = busy.clone();
    let notify_c = notify.clone();

    let join = tokio::spawn(async move {
        while !stop_c.load(Ordering::SeqCst) {
            if transport.is_closed() {
                if let Some(cb) = &on_transport_lost {
                    cb(session_id.clone());
                }
                break;
            }
            match pull_once(
                transport.as_ref(),
                &session_id,
                &inference,
                busy_c.clone(),
                on_desired_pool_target.as_ref(),
                answer_challenge.as_ref(),
                answer_ops_control.as_ref(),
            )
            .await
            {
                Ok(WorkPullOutcome::Idle) => {
                    // Idle 204 / empty: re-poll quickly (TS uses setImmediate).
                    tokio::select! {
                        _ = notify_c.notified() => {}
                        _ = tokio::time::sleep(Duration::from_millis(1)) => {}
                    }
                }
                Ok(WorkPullOutcome::Processed) => {}
                Err(err) => {
                    warn!(error = %err, session_id = %session_id, "pull worker error");
                    if transport.is_closed() {
                        if let Some(cb) = &on_transport_lost {
                            cb(session_id.clone());
                        }
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
    });

    PullWorkerHandle {
        stop,
        busy,
        notify,
        join,
    }
}

enum WorkPullOutcome {
    Idle,
    Processed,
}

async fn answer_challenge_work(
    transport: &dyn PlaneTransport,
    session_id: &str,
    request_id: &str,
    body: &[u8],
    answer_challenge: Option<&EngineChallengeHandler>,
) -> Result<WorkPullOutcome, PlaneError> {
    let result = match serde_json::from_slice::<crate::EngineChallengeWireRequest>(body) {
        Ok(request) if request.nonce_b64.trim().is_empty() => Err("nonce_b64_required".to_string()),
        Ok(mut request) => {
            request.nonce_b64 = request.nonce_b64.trim().to_string();
            request.epoch_id = request.epoch_id.map(|epoch_id| epoch_id.trim().to_string());
            match answer_challenge {
                Some(handler) => handler(request).await,
                None => Err("challenge_handler_unavailable".to_string()),
            }
        }
        Err(err) => Err(format!("challenge_request_json: {err}")),
    };

    let (status, response_body) = match result {
        Ok(response) => (
            200u16,
            serde_json::to_vec(&response).map_err(PlaneError::Json)?,
        ),
        Err(error) => (
            500u16,
            serde_json::to_vec(&serde_json::json!({ "error": error })).map_err(PlaneError::Json)?,
        ),
    };
    let status_header = status.to_string();
    let headers = [
        (HEADER_OPE_SESSION_ID, session_id),
        (HEADER_OPE_REQUEST_ID, request_id),
        ("x-ope-status", status_header.as_str()),
    ];
    let post = transport
        .request_bytes(
            "POST",
            ENGINE_PLANE_PATH_CHALLENGE_RESULT,
            Some(&response_body),
            Some("application/json"),
            &headers,
        )
        .await?;
    if post.status >= 400 {
        warn!(
            status = post.status,
            request_id, "challenge result rejected"
        );
    }
    info!(request_id, status, "engine challenge work answered");
    Ok(WorkPullOutcome::Processed)
}

async fn answer_ops_control_work(
    transport: &dyn PlaneTransport,
    session_id: &str,
    request_id: &str,
    body: &[u8],
    answer_ops_control: Option<&EngineOpsControlHandler>,
) -> Result<WorkPullOutcome, PlaneError> {
    let result = match serde_json::from_slice::<EngineOpsControlRequest>(body) {
        Ok(request) => match answer_ops_control {
            Some(handler) => handler(request).await,
            None => EngineOpsControlResult {
                ok: false,
                op: request.op,
                engine_id: String::new(),
                pool_target: None,
                live_sessions: None,
                draining: None,
                detail: None,
                error: Some("ops_control_handler_unavailable".into()),
            },
        },
        Err(err) => EngineOpsControlResult {
            ok: false,
            op: ie_protocol::EngineOpsControlOp::Status,
            engine_id: String::new(),
            pool_target: None,
            live_sessions: None,
            draining: None,
            detail: None,
            error: Some(format!("ops_control_request_json: {err}")),
        },
    };

    let status: u16 = if result.ok { 200 } else { 500 };
    let response_body = serde_json::to_vec(&result).map_err(PlaneError::Json)?;
    let status_header = status.to_string();
    let headers = [
        (HEADER_OPE_SESSION_ID, session_id),
        (HEADER_OPE_REQUEST_ID, request_id),
        ("x-ope-status", status_header.as_str()),
    ];
    let post = transport
        .request_bytes(
            "POST",
            ENGINE_PLANE_PATH_OPS_CONTROL_RESULT,
            Some(&response_body),
            Some("application/json"),
            &headers,
        )
        .await?;
    if post.status >= 400 {
        warn!(
            status = post.status,
            request_id, "ops_control result rejected"
        );
    }
    info!(request_id, status, ok = result.ok, "engine ops_control work answered");
    Ok(WorkPullOutcome::Processed)
}

async fn pull_once(
    transport: &dyn PlaneTransport,
    session_id: &str,
    inference: &OpeInferenceOptions,
    busy: Arc<AtomicBool>,
    on_desired_pool_target: Option<&DesiredPoolTargetCallback>,
    answer_challenge: Option<&EngineChallengeHandler>,
    answer_ops_control: Option<&EngineOpsControlHandler>,
) -> Result<WorkPullOutcome, PlaneError> {
    let resp = transport
        .request_bytes(
            "GET",
            ENGINE_PLANE_PATH_WORK_PULL,
            None,
            None,
            &[(HEADER_OPE_SESSION_ID, session_id)],
        )
        .await?;

    if let Some(desired) =
        parse_desired_pool_target_header(resp.header_value(HEADER_OPE_DESIRED_POOL_TARGET))
    {
        if let Some(cb) = on_desired_pool_target {
            cb(desired);
        }
    }

    if resp.status != 200 || resp.body.is_empty() {
        return Ok(WorkPullOutcome::Idle);
    }

    let request_id = resp
        .header_value(HEADER_OPE_REQUEST_ID)
        .unwrap_or("")
        .to_string();
    if request_id.is_empty() {
        return Ok(WorkPullOutcome::Idle);
    }

    if resp.header_value(HEADER_OPE_WORK_KIND) == Some(OPE_WORK_KIND_CHALLENGE) {
        busy.store(true, Ordering::SeqCst);
        let result = answer_challenge_work(
            transport,
            session_id,
            &request_id,
            &resp.body,
            answer_challenge,
        )
        .await;
        busy.store(false, Ordering::SeqCst);
        return result;
    }

    if resp.header_value(HEADER_OPE_WORK_KIND) == Some(OPE_WORK_KIND_OPS_CONTROL) {
        busy.store(true, Ordering::SeqCst);
        let result = answer_ops_control_work(
            transport,
            session_id,
            &request_id,
            &resp.body,
            answer_ops_control,
        )
        .await;
        busy.store(false, Ordering::SeqCst);
        return result;
    }

    let traffic_class_header = resp
        .header_value(HEADER_OPE_TRAFFIC_CLASS)
        .map(str::to_string);

    let envelope: OpeEnvelope = serde_json::from_slice(&resp.body)
        .map_err(|e| PlaneError::H2(format!("work envelope json: {e}")))?;

    match traffic_class_header_meta_consistent(
        traffic_class_header.as_deref(),
        envelope
            .meta
            .as_ref()
            .and_then(|m| m.traffic_class.as_deref()),
    ) {
        TrafficClassConsistency::Ok { .. } => {}
        TrafficClassConsistency::Mismatch { header, meta } => {
            return Err(PlaneError::H2(format!(
                "ope_traffic_class_invalid: traffic_class mismatch: header={} meta={}",
                header.as_str(),
                meta.as_str()
            )));
        }
        TrafficClassConsistency::Missing => {
            return Err(PlaneError::H2(
                "ope_traffic_class_invalid: traffic_class missing".into(),
            ));
        }
    }

    busy.store(true, Ordering::SeqCst);
    let started = std::time::Instant::now();

    let inference_opts = OpeInferenceOptions {
        request_id: Some(request_id.clone()),
        decrypt_handle: inference.decrypt_handle,
        rotating: inference.rotating.clone(),
        provider: Arc::clone(&inference.provider),
        vllm_base_url: inference.vllm_base_url.clone(),
        vllm_api_key: inference.vllm_api_key.clone(),
        task_vllm_base_url: inference.task_vllm_base_url.clone(),
        task_vllm_api_key: inference.task_vllm_api_key.clone(),
        task_model_id: inference.task_model_id.clone(),
        embeddings_base_url: inference.embeddings_base_url.clone(),
        embeddings_api_key: inference.embeddings_api_key.clone(),
        embeddings_default_model: inference.embeddings_default_model.clone(),
        vllm: VllmChatClient::default(),
        chunk_chars: inference.chunk_chars,
        kv: inference.kv.clone(),
        usage_signing_key: inference.usage_signing_key.clone(),
        admitter: inference.admitter.clone(),
    };

    let post = if is_gateway_plane_task_envelope(&envelope)
        || !matches!(validate_ope_inference_envelope(&envelope), GateResult::Ok)
    {
        // Non-streaming: gateway-plane-task or gate reject (JSON error body).
        let mut stream_buf = Vec::new();
        let result = run_ope_inference_on_envelope(
            &envelope,
            &inference_opts,
            Some(&mut stream_buf as &mut dyn NdjsonStreamWriter),
        )
        .await;
        let content_type = if result.content_type.contains("ope+json-stream") {
            CONTENT_TYPE_OPE_JSON_STREAM
        } else if result.content_type.contains("ope+json") {
            CONTENT_TYPE_OPE_JSON
        } else {
            "application/json"
        };
        let body_bytes = if content_type == CONTENT_TYPE_OPE_JSON_STREAM {
            stream_buf
        } else {
            result.body.into_bytes()
        };
        let status_owned = result.status.to_string();
        let mut headers_owned: Vec<(String, String)> = vec![
            (HEADER_OPE_SESSION_ID.to_string(), session_id.to_string()),
            (HEADER_OPE_REQUEST_ID.to_string(), request_id.clone()),
            ("x-ope-status".into(), status_owned),
        ];
        if let Some(u) = &result.usage_header {
            headers_owned.push((HEADER_USAGE_REPORT.to_string(), u.clone()));
        }
        let header_refs: Vec<(&str, &str)> = headers_owned
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        transport
            .request_bytes(
                "POST",
                ENGINE_PLANE_PATH_INFERENCE_RESULT,
                Some(&body_bytes),
                Some(content_type),
                &header_refs,
            )
            .await?
    } else {
        // Match TS: open inference/result early and flush NDJSON as vLLM tokens arrive.
        let status_owned = "200".to_string();
        let headers_owned: Vec<(String, String)> = vec![
            (HEADER_OPE_SESSION_ID.to_string(), session_id.to_string()),
            (HEADER_OPE_REQUEST_ID.to_string(), request_id.clone()),
            ("x-ope-status".into(), status_owned),
        ];
        let header_refs: Vec<(&str, &str)> = headers_owned
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let mut handle = transport
            .open_streaming_bytes_post(
                ENGINE_PLANE_PATH_INFERENCE_RESULT,
                CONTENT_TYPE_OPE_JSON_STREAM,
                &header_refs,
            )
            .await?;

        struct LiveNdjson<'a>(&'a mut StreamingPostHandle);
        impl NdjsonStreamWriter for LiveNdjson<'_> {
            fn write(&mut self, chunk: &[u8]) {
                self.0.write(chunk);
            }
            fn end(&mut self) {}
        }

        let mut writer = LiveNdjson(&mut handle);
        let result = run_ope_inference_on_envelope(
            &envelope,
            &inference_opts,
            Some(&mut writer as &mut dyn NdjsonStreamWriter),
        )
        .await;

        // Only finish the speculative stream when inference actually produced a
        // successful OPE stream. Upstream failures (e.g. vLLM 400 context length)
        // return application/json + 4xx/5xx — abort and re-POST so x-ope-status
        // matches (headers on the first open are already committed as 200).
        let stream_ok = result.status < 400 && result.content_type.contains("ope+json-stream");
        if stream_ok {
            handle.finish().await?
        } else {
            handle.abort();
            let status_owned = result.status.to_string();
            let mut headers_owned: Vec<(String, String)> = vec![
                (HEADER_OPE_SESSION_ID.to_string(), session_id.to_string()),
                (HEADER_OPE_REQUEST_ID.to_string(), request_id.clone()),
                ("x-ope-status".into(), status_owned),
            ];
            if let Some(u) = &result.usage_header {
                headers_owned.push((HEADER_USAGE_REPORT.to_string(), u.clone()));
            }
            let header_refs: Vec<(&str, &str)> = headers_owned
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            transport
                .request_bytes(
                    "POST",
                    ENGINE_PLANE_PATH_INFERENCE_RESULT,
                    Some(result.body.as_bytes()),
                    Some("application/json"),
                    &header_refs,
                )
                .await?
        }
    };

    if post.status >= 400 {
        warn!(
            status = post.status,
            request_id = %request_id,
            "inference result rejected"
        );
    }

    info!(
        request_id = %request_id,
        elapsed_ms = started.elapsed().as_millis() as u64,
        "engine work assigned"
    );
    busy.store(false, Ordering::SeqCst);
    Ok(WorkPullOutcome::Processed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use bytes::Bytes;
    use ie_crypto::{CryptoProvider, MockCryptoProvider};
    use ie_protocol::{
        CpuTeeEndorsement, EngineOpsControlOp, EngineOpsControlRequest, EngineOpsControlResult,
        ENGINE_PLANE_PATH_CHALLENGE_RESULT, ENGINE_PLANE_PATH_OPS_CONTROL_RESULT,
        HEADER_OPE_WORK_KIND, OPE_WORK_KIND_CHALLENGE, OPE_WORK_KIND_OPS_CONTROL,
    };
    use std::sync::Mutex;

    use crate::{
        EngineChallengeCpuResponse, EngineChallengeEngineResponse, EngineChallengeEpoch,
        EngineChallengeMeasurement, EngineChallengeWireResponse, H2BytesResponse, H2JsonResponse,
    };

    #[derive(Default)]
    struct ChallengeTransport {
        pull: Mutex<Option<H2BytesResponse>>,
        posted: Mutex<Option<(String, Vec<(String, String)>, Bytes)>>,
    }

    #[async_trait]
    impl PlaneTransport for ChallengeTransport {
        async fn request_json(
            &self,
            _method: &str,
            _path: &str,
            _body: Option<&serde_json::Value>,
            _headers: &[(&str, &str)],
        ) -> Result<H2JsonResponse, PlaneError> {
            Err(PlaneError::H2("unexpected request_json".into()))
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
                return Ok(self.pull.lock().unwrap().take().unwrap_or(H2BytesResponse {
                    status: 204,
                    headers: vec![],
                    body: Bytes::new(),
                }));
            }
            if method == "POST" && path == ENGINE_PLANE_PATH_CHALLENGE_RESULT {
                *self.posted.lock().unwrap() = Some((
                    path.to_string(),
                    headers
                        .iter()
                        .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
                        .collect(),
                    Bytes::copy_from_slice(body.unwrap_or_default()),
                ));
                return Ok(H2BytesResponse {
                    status: 200,
                    headers: vec![],
                    body: Bytes::new(),
                });
            }
            if method == "POST" && path == ENGINE_PLANE_PATH_OPS_CONTROL_RESULT {
                *self.posted.lock().unwrap() = Some((
                    path.to_string(),
                    headers
                        .iter()
                        .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
                        .collect(),
                    Bytes::copy_from_slice(body.unwrap_or_default()),
                ));
                return Ok(H2BytesResponse {
                    status: 204,
                    headers: vec![],
                    body: Bytes::new(),
                });
            }
            Err(PlaneError::H2(format!("unexpected {method} {path}")))
        }

        async fn close(&self) -> Result<(), PlaneError> {
            Ok(())
        }
    }

    fn inference_options() -> OpeInferenceOptions {
        OpeInferenceOptions {
            request_id: None,
            decrypt_handle: 0,
            rotating: None,
            provider: Arc::new(MockCryptoProvider::new()) as Arc<dyn CryptoProvider>,
            vllm_base_url: String::new(),
            vllm_api_key: None,
            task_vllm_base_url: None,
            task_vllm_api_key: None,
            task_model_id: None,
            embeddings_base_url: None,
            embeddings_api_key: None,
            embeddings_default_model: None,
            vllm: VllmChatClient::default(),
            chunk_chars: 8,
            kv: None,
            usage_signing_key: None,
            admitter: None,
        }
    }

    fn challenge_response(nonce_b64: String) -> EngineChallengeWireResponse {
        EngineChallengeWireResponse {
            schema_version: 1,
            report_data_version: 1,
            engine: EngineChallengeEngineResponse {
                engine_id: "eng-1".into(),
                build_version: "0.15.0".into(),
                measurement: EngineChallengeMeasurement::LaunchDigest {
                    launch_digest: "a".repeat(64),
                    image_digest: "b".repeat(64),
                },
                policy_hash: "c".repeat(64),
            },
            epoch: EngineChallengeEpoch {
                epoch_id: "ep-1".into(),
                not_before: "2026-08-01T00:00:00.000Z".into(),
                not_after: "2026-08-02T00:00:00.000Z".into(),
                mlkem_encapsulation_key: "bWxrZW0=".into(),
                x25519_public: "eDI1NTE5".into(),
                usage_signing_public: "dXNhZ2U=".into(),
            },
            challenge_nonce_b64: nonce_b64,
            cpu: EngineChallengeCpuResponse {
                quote_format: "snp_report".into(),
                quote_b64: "cXVvdGU=".into(),
                endorsement: CpuTeeEndorsement {
                    vcek_der_b64: "dmNlaw==".into(),
                    ask_der_b64: None,
                    ark_der_b64: None,
                    crl_der_b64: None,
                },
            },
            gpu: None,
        }
    }

    #[tokio::test]
    async fn challenge_work_posts_challenge_result_without_parsing_an_ope_envelope() {
        let nonce_b64 = crate::encode_nonce_b64_url(&[7u8; 32]);
        let transport = ChallengeTransport {
            pull: Mutex::new(Some(H2BytesResponse {
                status: 200,
                headers: vec![
                    (HEADER_OPE_REQUEST_ID.into(), "req-challenge".into()),
                    (HEADER_OPE_WORK_KIND.into(), OPE_WORK_KIND_CHALLENGE.into()),
                ],
                body: Bytes::from(
                    serde_json::to_vec(&serde_json::json!({
                        "nonce_b64": nonce_b64.clone(),
                        "epoch_id": "ep-1"
                    }))
                    .unwrap(),
                ),
            })),
            posted: Mutex::new(None),
        };
        let expected_nonce = nonce_b64.clone();
        let handler: EngineChallengeHandler = Arc::new(move |request| {
            assert_eq!(request.nonce_b64, expected_nonce);
            assert_eq!(request.epoch_id.as_deref(), Some("ep-1"));
            let response = challenge_response(request.nonce_b64);
            Box::pin(async move { Ok(response) })
        });
        let busy = Arc::new(AtomicBool::new(false));

        let outcome = pull_once(
            &transport,
            "sess-1",
            &inference_options(),
            Arc::clone(&busy),
            None,
            Some(&handler),
            None,
        )
        .await
        .expect("challenge work");
        assert!(matches!(outcome, WorkPullOutcome::Processed));
        assert!(!busy.load(Ordering::SeqCst));

        let (path, headers, body) = transport.posted.lock().unwrap().clone().expect("result");
        assert_eq!(path, ENGINE_PLANE_PATH_CHALLENGE_RESULT);
        assert!(headers
            .iter()
            .any(|(name, value)| name == HEADER_OPE_SESSION_ID && value == "sess-1"));
        assert!(headers
            .iter()
            .any(|(name, value)| name == HEADER_OPE_REQUEST_ID && value == "req-challenge"));
        assert!(headers
            .iter()
            .any(|(name, value)| name == "x-ope-status" && value == "200"));
        let response: EngineChallengeWireResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(response.challenge_nonce_b64, nonce_b64);
    }

    #[tokio::test]
    async fn ops_control_work_posts_result_without_parsing_an_ope_envelope() {
        let transport = ChallengeTransport {
            pull: Mutex::new(Some(H2BytesResponse {
                status: 200,
                headers: vec![
                    (HEADER_OPE_REQUEST_ID.into(), "req-ops".into()),
                    (HEADER_OPE_WORK_KIND.into(), OPE_WORK_KIND_OPS_CONTROL.into()),
                ],
                body: Bytes::from(
                    serde_json::to_vec(&EngineOpsControlRequest {
                        op: EngineOpsControlOp::ForceTarget,
                        target_size: Some(8),
                        drain_fraction: None,
                        drain_count: None,
                        migrate_url: None,
                        migrate_fraction: None,
                        confirm: None,
                    })
                    .unwrap(),
                ),
            })),
            posted: Mutex::new(None),
        };
        let handler: EngineOpsControlHandler = Arc::new(|request| {
            assert_eq!(request.op, EngineOpsControlOp::ForceTarget);
            assert_eq!(request.target_size, Some(8));
            Box::pin(async move {
                EngineOpsControlResult {
                    ok: true,
                    op: request.op,
                    engine_id: "eng-1".into(),
                    pool_target: request.target_size,
                    live_sessions: Some(8),
                    draining: None,
                    detail: Some("forced_to_8".into()),
                    error: None,
                }
            })
        });
        let busy = Arc::new(AtomicBool::new(false));

        let outcome = pull_once(
            &transport,
            "sess-1",
            &inference_options(),
            Arc::clone(&busy),
            None,
            None,
            Some(&handler),
        )
        .await
        .expect("ops_control work");
        assert!(matches!(outcome, WorkPullOutcome::Processed));
        assert!(!busy.load(Ordering::SeqCst));

        let (path, headers, body) = transport.posted.lock().unwrap().clone().expect("result");
        assert_eq!(path, ENGINE_PLANE_PATH_OPS_CONTROL_RESULT);
        assert!(headers
            .iter()
            .any(|(name, value)| name == HEADER_OPE_SESSION_ID && value == "sess-1"));
        assert!(headers
            .iter()
            .any(|(name, value)| name == HEADER_OPE_REQUEST_ID && value == "req-ops"));
        assert!(headers
            .iter()
            .any(|(name, value)| name == "x-ope-status" && value == "200"));
        let response: EngineOpsControlResult = serde_json::from_slice(&body).unwrap();
        assert!(response.ok);
        assert_eq!(response.pool_target, Some(8));
        assert_eq!(response.engine_id, "eng-1");
    }

    #[tokio::test]
    async fn ops_control_posts_error_result_when_handler_missing() {
        let transport = ChallengeTransport {
            pull: Mutex::new(Some(H2BytesResponse {
                status: 200,
                headers: vec![
                    (HEADER_OPE_REQUEST_ID.into(), "req-ops-missing".into()),
                    (HEADER_OPE_WORK_KIND.into(), OPE_WORK_KIND_OPS_CONTROL.into()),
                ],
                body: Bytes::from(
                    serde_json::to_vec(&EngineOpsControlRequest {
                        op: EngineOpsControlOp::Status,
                        target_size: None,
                        drain_fraction: None,
                        drain_count: None,
                        migrate_url: None,
                        migrate_fraction: None,
                        confirm: None,
                    })
                    .unwrap(),
                ),
            })),
            posted: Mutex::new(None),
        };
        let busy = Arc::new(AtomicBool::new(false));
        let outcome = pull_once(
            &transport,
            "sess-1",
            &inference_options(),
            Arc::clone(&busy),
            None,
            None,
            None,
        )
        .await
        .expect("ops_control without handler");
        assert!(matches!(outcome, WorkPullOutcome::Processed));
        let (path, headers, body) = transport.posted.lock().unwrap().clone().expect("result");
        assert_eq!(path, ENGINE_PLANE_PATH_OPS_CONTROL_RESULT);
        assert!(headers
            .iter()
            .any(|(name, value)| name == "x-ope-status" && value == "500"));
        let response: EngineOpsControlResult = serde_json::from_slice(&body).unwrap();
        assert!(!response.ok);
        assert_eq!(
            response.error.as_deref(),
            Some("ops_control_handler_unavailable")
        );
    }

    #[tokio::test]
    async fn ops_control_posts_error_result_for_invalid_json() {
        let transport = ChallengeTransport {
            pull: Mutex::new(Some(H2BytesResponse {
                status: 200,
                headers: vec![
                    (HEADER_OPE_REQUEST_ID.into(), "req-ops-bad".into()),
                    (HEADER_OPE_WORK_KIND.into(), OPE_WORK_KIND_OPS_CONTROL.into()),
                ],
                body: Bytes::from_static(b"{not-json"),
            })),
            posted: Mutex::new(None),
        };
        let handler: EngineOpsControlHandler = Arc::new(|_| {
            Box::pin(async {
                panic!("handler must not run on invalid json");
            })
        });
        let busy = Arc::new(AtomicBool::new(false));
        let outcome = pull_once(
            &transport,
            "sess-1",
            &inference_options(),
            Arc::clone(&busy),
            None,
            None,
            Some(&handler),
        )
        .await
        .expect("ops_control bad json");
        assert!(matches!(outcome, WorkPullOutcome::Processed));
        let (_, headers, body) = transport.posted.lock().unwrap().clone().expect("result");
        assert!(headers
            .iter()
            .any(|(name, value)| name == "x-ope-status" && value == "500"));
        let response: EngineOpsControlResult = serde_json::from_slice(&body).unwrap();
        assert!(!response.ok);
        assert!(response
            .error
            .as_deref()
            .unwrap_or("")
            .starts_with("ops_control_request_json:"));
    }
}
