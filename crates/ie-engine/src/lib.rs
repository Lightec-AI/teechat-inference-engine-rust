//! Supervised engine plane pool skeleton (port of `engine/supervised-pool.ts`).

mod config;
mod error;
mod plane;
mod pool;
mod traits;

pub use config::{PoolReconnectConfig, SupervisedPoolConfig};
pub use error::EngineError;
pub use plane::{
    build_connect_request, generate_gateway_connect_challenge_nonce,
    graceful_disconnect_attested_session, is_valid_gateway_connect_challenge_nonce,
    normalize_gateway_connect_challenge_nonce, open_pooled_connection,
    open_pooled_connection_on_transport, post_disconnect_on_attested_session,
    post_ephemeral_on_attested_session, AttestedH2Session, EnginePlaneDialOptions,
    GatewayAttestationVerifier, H2JsonResponse, Http2EnginePlaneConnector,
    NonceEchoGatewayAttestationVerifier, NullGatewayAttestationVerifier, PlaneError,
    PlaneTransport,
};
pub use pool::{PoolSession, SupervisedPool, SupervisedPoolHandle};
pub use traits::{ConnectResult, EnginePlaneConnector, InferResult, InferenceUpstream};
