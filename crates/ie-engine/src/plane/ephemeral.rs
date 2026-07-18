use ie_protocol::{EngineEphemeralRegisterRequest, ENGINE_PLANE_PATH_EPHEMERAL, HEADER_OPE_SESSION_ID};

use super::error::PlaneError;
use super::session::{AttestedH2Session, H2JsonResponse};

pub async fn post_ephemeral_on_attested_session(
    session: &AttestedH2Session,
    body: &EngineEphemeralRegisterRequest,
) -> Result<H2JsonResponse, PlaneError> {
    session
        .request_json(
            "POST",
            ENGINE_PLANE_PATH_EPHEMERAL,
            Some(body),
            &[(HEADER_OPE_SESSION_ID, session.session_id())],
        )
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plane::session::PlaneTransport;
    use async_trait::async_trait;
    use ie_protocol::EngineHybridPublic;
    use serde_json::json;
    use std::sync::Mutex;

    #[tokio::test]
    async fn ephemeral_posts_with_session_header() {
        let seen = std::sync::Arc::new(Mutex::new(Vec::<(String, String)>::new()));
        struct Rec {
            seen: std::sync::Arc<Mutex<Vec<(String, String)>>>,
        }
        #[async_trait]
        impl PlaneTransport for Rec {
            async fn request_json(
                &self,
                method: &str,
                path: &str,
                _body: Option<&serde_json::Value>,
                headers: &[(&str, &str)],
            ) -> Result<H2JsonResponse, PlaneError> {
                let hdr = headers
                    .iter()
                    .find(|(k, _)| *k == HEADER_OPE_SESSION_ID)
                    .map(|(_, v)| (*v).to_string())
                    .unwrap_or_default();
                self.seen.lock().unwrap().push((format!("{method} {path}"), hdr));
                Ok(H2JsonResponse {
                    status: 201,
                    json: json!({ "ok": true }),
                })
            }
            async fn close(self: Box<Self>) -> Result<(), PlaneError> {
                Ok(())
            }
        }
        let session = AttestedH2Session::from_transport(
            "sess-42".into(),
            Box::new(Rec { seen: seen.clone() }),
        );
        let body = EngineEphemeralRegisterRequest {
            engine_id: "e".into(),
            epoch_id: "ep".into(),
            hybrid: EngineHybridPublic {
                kex: "k".into(),
                mlkem_encapsulation_key: "m".into(),
                x25519_public: "x".into(),
            },
            identity_signature: "sig".into(),
            not_before: "n".into(),
            not_after: "a".into(),
            attestation: None,
        };
        let resp = post_ephemeral_on_attested_session(&session, &body)
            .await
            .unwrap();
        assert_eq!(resp.status, 201);
        let rows = seen.lock().unwrap().clone();
        assert_eq!(rows[0].0, format!("POST {ENGINE_PLANE_PATH_EPHEMERAL}"));
        assert_eq!(rows[0].1, "sess-42");
    }
}
