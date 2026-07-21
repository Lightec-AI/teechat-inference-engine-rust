//! Work-pull loop (port of `startPullWorker` in `engine-plane/pool-client.ts`).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ie_protocol::{
    traffic_class_header_meta_consistent, OpeEnvelope, TrafficClassConsistency,
    CONTENT_TYPE_OPE_JSON, CONTENT_TYPE_OPE_JSON_STREAM, ENGINE_PLANE_PATH_INFERENCE_RESULT,
    ENGINE_PLANE_PATH_WORK_PULL, HEADER_OPE_REQUEST_ID, HEADER_OPE_SESSION_ID,
    HEADER_OPE_TRAFFIC_CLASS, HEADER_USAGE_REPORT,
};
use tokio::sync::Notify;
use tracing::{info, warn};

use crate::desired_pool::{
    parse_desired_pool_target_header, DesiredPoolTargetCallback, HEADER_OPE_DESIRED_POOL_TARGET,
};
use crate::infer::{
    is_gateway_plane_task_envelope, run_ope_inference_on_envelope, NdjsonStreamWriter,
    OpeInferenceOptions, validate_ope_inference_envelope, GateResult,
};
use ie_upstream::VllmChatClient;

use super::error::PlaneError;
use super::session::{PlaneTransport, StreamingPostHandle};

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

async fn pull_once(
    transport: &dyn PlaneTransport,
    session_id: &str,
    inference: &OpeInferenceOptions,
    busy: Arc<AtomicBool>,
    on_desired_pool_target: Option<&DesiredPoolTargetCallback>,
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

    let traffic_class_header = resp.header_value(HEADER_OPE_TRAFFIC_CLASS).map(str::to_string);

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
        vllm: VllmChatClient::default(),
        chunk_chars: inference.chunk_chars,
        kv: inference.kv.clone(),
        usage_signing_key: inference.usage_signing_key.clone(),
    };

    let post = if is_gateway_plane_task_envelope(&envelope)
        || !matches!(
            validate_ope_inference_envelope(&envelope),
            GateResult::Ok
        )
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
