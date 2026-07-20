//! Supervised engine plane pool, epoch rotation, and runtime controls.

mod config;
mod controls;
mod cutover;
mod epoch;
mod error;
mod gateway_migration;
mod infer;
mod ops;
mod plane;
mod pool;
mod traits;

pub use config::{PoolReconnectConfig, SupervisedPoolConfig};
pub use controls::{
    build_pool_status_snapshot, default_gateway_migration_file, default_pool_drain_file,
    default_pool_scale_file, default_pool_status_file, install_engine_controls,
    read_gateway_migration_request_file, read_pool_drain_request_file, read_pool_scale_request_file,
    resolve_control_file_path, write_pool_status_file, EnginePoolStatusSnapshot,
    GatewayMigrationControl, InstalledControls, PoolDrainControl, PoolScaleControl,
    PoolStatusControl, ENGINE_POOL_STATUS_SCHEMA,
};
pub use cutover::{
    create_pool_connect_throttle_from_env, initial_pool_session_count, map_with_concurrency,
    parse_pool_drain_request_json, parse_pool_scale_request_json, plan_pool_drain,
    plan_pool_scale, pool_connect_concurrency_from_env, pool_connect_stagger_ms_from_env,
    pool_initial_fraction_from_env, PoolConnectThrottle, PoolDrainPlan, PoolDrainRequest,
    PoolScalePlan, PoolScaleRequest,
};
pub use epoch::{
    compute_epoch_rotate_at_ms, create_engine_epoch, dispose_engine_epoch, epoch_rotation_lead_ms_from_env,
    epoch_rotation_policy_from_env, epoch_ttl_ms_from_policy, CreateEngineEpochArgs, EngineEpoch,
    EphemeralPoster, EpochRotatedCallback, EpochRotationPolicy, EpochRotator, EpochRotatorSession,
    RotatingEpochDecryptor,
};
pub use error::EngineError;
pub use gateway_migration::{
    parse_gateway_migration_request_json, plan_gateway_migration, GatewayMigrationPlan,
    GatewayMigrationRequest,
};
pub use ops::{
    configure_event_log_from_env, conversation_kv_key, engine_instance_id_from_env,
    ephemeral_signing_bytes, is_epoch_active, log_event, normalize_engine_instance_id,
    plan_vllm_prefill, sign_usage_report, usage_report_signing_bytes, verify_usage_report,
    ConversationKvState, EventLogLevel, PrefillPlan, DEFAULT_ENGINE_INSTANCE_ID,
};
pub use infer::{
    ope_inference_reject_body, run_ope_inference_on_envelope, validate_ope_inference_content_type,
    validate_ope_inference_envelope, GateResult, NdjsonStreamWriter, OpeInferenceGateError,
    OpeInferenceOptions, OpeInferenceResult,
};
pub use plane::{
    build_connect_request, generate_gateway_connect_challenge_nonce,
    graceful_disconnect_attested_session, is_valid_gateway_connect_challenge_nonce,
    normalize_gateway_connect_challenge_nonce, open_pooled_connection,
    open_pooled_connection_on_transport, post_disconnect_on_attested_session,
    post_ephemeral_on_attested_session, start_pull_worker, AttestedH2Session,
    EnginePlaneDialOptions, GatewayAttestationVerifier, H2BytesResponse, H2JsonResponse,
    Http2EnginePlaneConnector, NonceEchoGatewayAttestationVerifier,
    NullGatewayAttestationVerifier, PlaneError, PlaneTransport, PullWorkerHandle,
    StreamingPostHandle,
};
pub use pool::{
    sessions_by_gateway_url_from_slots, GatewayMigrationResult, PoolDrainResult, PoolScaleResult,
    PoolSession, SupervisedPool, SupervisedPoolHandle,
};
pub use traits::{ConnectResult, EnginePlaneConnector, InferResult, InferenceUpstream};
