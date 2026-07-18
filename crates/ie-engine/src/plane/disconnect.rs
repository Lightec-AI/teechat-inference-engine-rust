use std::time::Duration;

use ie_protocol::{
    AttestedDisconnectReason, AttestedDisconnectRequest, AttestedDisconnectResponse,
    ENGINE_PLANE_PATH_DISCONNECT, HEADER_OPE_SESSION_ID,
};
use tokio::time::{sleep, Instant};

use super::error::PlaneError;
use super::session::AttestedH2Session;

pub async fn post_disconnect_on_attested_session(
    session: &AttestedH2Session,
    engine_id: &str,
    reason: AttestedDisconnectReason,
) -> Result<AttestedDisconnectResponse, PlaneError> {
    let body = AttestedDisconnectRequest {
        engine_id: engine_id.to_string(),
        session_id: session.session_id().to_string(),
        reason: Some(reason),
    };
    let resp = session
        .request_json(
            "POST",
            ENGINE_PLANE_PATH_DISCONNECT,
            Some(&body),
            &[(HEADER_OPE_SESSION_ID, session.session_id())],
        )
        .await?;
    if resp.status == 0 {
        return Ok(AttestedDisconnectResponse {
            ok: false,
            draining: true,
            in_flight: 0,
            ready_to_close: false,
            engine_deregistered: None,
        });
    }
    if resp.status != 200 {
        return Ok(AttestedDisconnectResponse {
            ok: false,
            draining: true,
            in_flight: 0,
            ready_to_close: false,
            engine_deregistered: None,
        });
    }
    Ok(serde_json::from_value(resp.json)?)
}

/// Poll disconnect until `ready_to_close` (TS `gracefulDisconnectAttestedSession`).
pub async fn graceful_disconnect_attested_session(
    session: &AttestedH2Session,
    engine_id: &str,
    reason: AttestedDisconnectReason,
    timeout: Duration,
    poll_interval: Duration,
) -> Result<(), PlaneError> {
    let deadline = Instant::now() + timeout;
    loop {
        let resp = post_disconnect_on_attested_session(session, engine_id, reason).await?;
        if resp.ready_to_close {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(PlaneError::DisconnectTimeout);
        }
        sleep(poll_interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plane::session::{H2JsonResponse, PlaneTransport};
    use async_trait::async_trait;
    use serde_json::json;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct PollTransport {
        calls: AtomicU32,
    }

    #[async_trait]
    impl PlaneTransport for PollTransport {
        async fn request_json(
            &self,
            _method: &str,
            _path: &str,
            _body: Option<&serde_json::Value>,
            _headers: &[(&str, &str)],
        ) -> Result<H2JsonResponse, PlaneError> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            let ready = n >= 1;
            Ok(H2JsonResponse {
                status: 200,
                json: json!({
                    "ok": true,
                    "draining": !ready,
                    "in_flight": if ready { 0 } else { 1 },
                    "ready_to_close": ready,
                }),
            })
        }
        async fn close(self: Box<Self>) -> Result<(), PlaneError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn graceful_disconnect_waits_for_ready() {
        let session = AttestedH2Session::from_transport(
            "sess".into(),
            Box::new(PollTransport {
                calls: AtomicU32::new(0),
            }),
        );
        graceful_disconnect_attested_session(
            &session,
            "eng",
            AttestedDisconnectReason::Shutdown,
            Duration::from_secs(2),
            Duration::from_millis(1),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn graceful_disconnect_timeout() {
        struct AlwaysBusy;
        #[async_trait]
        impl PlaneTransport for AlwaysBusy {
            async fn request_json(
                &self,
                _method: &str,
                _path: &str,
                _body: Option<&serde_json::Value>,
                _headers: &[(&str, &str)],
            ) -> Result<H2JsonResponse, PlaneError> {
                Ok(H2JsonResponse {
                    status: 200,
                    json: json!({
                        "ok": true,
                        "draining": true,
                        "in_flight": 1,
                        "ready_to_close": false,
                    }),
                })
            }
            async fn close(self: Box<Self>) -> Result<(), PlaneError> {
                Ok(())
            }
        }
        let session =
            AttestedH2Session::from_transport("sess".into(), Box::new(AlwaysBusy));
        let err = graceful_disconnect_attested_session(
            &session,
            "eng",
            AttestedDisconnectReason::Shutdown,
            Duration::from_millis(20),
            Duration::from_millis(5),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, PlaneError::DisconnectTimeout));
    }
}
