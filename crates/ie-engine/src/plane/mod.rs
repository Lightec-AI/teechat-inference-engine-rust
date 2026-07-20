//! Engine-plane HTTP/2 + attested TLS dial (port of `engine-plane/pool-client.ts`).

mod challenge;
mod connect;
mod connector;
mod disconnect;
mod ephemeral;
mod error;
mod gateway_platform_verify;
mod hyper_transport;
mod pull;
mod session;
mod verify;

pub use challenge::{
    generate_gateway_connect_challenge_nonce, is_valid_gateway_connect_challenge_nonce,
    normalize_gateway_connect_challenge_nonce,
};
pub use connect::{
    build_connect_request, open_pooled_connection, open_pooled_connection_on_transport,
    EnginePlaneDialOptions,
};
pub use connector::Http2EnginePlaneConnector;
pub use disconnect::{
    graceful_disconnect_attested_session, post_disconnect_on_attested_session,
};
pub use ephemeral::post_ephemeral_on_attested_session;
pub use error::PlaneError;
pub use gateway_platform_verify::platform_policy_verifier_from_env;
pub use pull::{start_pull_worker, PullWorkerHandle};
pub use session::{
    AttestedH2Session, H2BytesResponse, H2JsonResponse, PlaneTransport, StreamingPostHandle,
};
pub use verify::{
    GatewayAttestationVerifier, NonceEchoGatewayAttestationVerifier, NullGatewayAttestationVerifier,
    PlatformPolicyGatewayAttestationVerifier,
};
