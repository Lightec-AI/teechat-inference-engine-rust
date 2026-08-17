use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use clap::Parser;
use ed25519_dalek::SigningKey;
use ie_attestation::{
    build_engine_attestation_bundle, build_engine_epoch_attestation_bundle,
    create_engine_attestation_refresher, load_tcb_pins, validate_tcb_pins,
    EngineAttestationRefreshContext, QuoteEpochClaims,
};
use ie_crypto::{MockCryptoProvider, RealCryptoProvider};
use ie_engine::{
    apply_engine_ops_control, configure_event_log_from_env, create_pool_connect_throttle_from_env,
    engine_instance_id_from_env, epoch_rotation_policy_from_env,
    generate_gateway_connect_challenge_nonce, install_engine_controls,
    mint_engine_challenge_response, platform_policy_verifier_from_env, spawn_desired_pool_applier,
    start_pull_worker, warn_pull_worker_start, DesiredPoolTargetCallback, EngineChallengeEpoch,
    EngineChallengeHandler, EngineChallengeMeasurement, EngineOpsControlHandler,
    EnginePlaneDialOptions, EphemeralPoster, EpochEvidenceMinter, EpochRotatedCallback,
    EpochRotator, EpochRotatorOptions, EpochRotatorSession, Http2EnginePlaneConnector,
    MintEngineChallengeArgs, OpeInferenceOptions, OpsControlRateLimiter, PullWorkerStartFn,
    RotatingEpochDecryptor, SupervisedPool, SupervisedPoolConfig,
};
use ie_protocol::{
    AttestedConnectRequest, EngineEphemeralRegisterRequest, CAPABILITY_OPS_CONTROL_V1,
};
use ie_runtime::{engine_plane_client_tls, env_map_from_process, load_engine_env_files};
use ie_upstream::{
    embed_model_id_from_env, embeddings_config_from_env, max_tokens_from_env,
    open_ai_chat_completions_url, task_model_id_from_env, vllm_task_config_from_env,
    VllmChatClient,
};
use ope_crypto::{encode, mock_keypair_from_seed, DEV_VECTOR_001_SEED};
use rand::rngs::OsRng;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

mod shutdown;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser, Debug)]
#[command(
    name = "teechat-inference-engine",
    about = "TeeChat InferenceEngine (Rust) — decrypt/pool/vLLM/attest control plane",
    version = VERSION
)]
struct Cli {
    /// Validate TCB pins JSON (default: config/tcb-pins.json).
    #[arg(long, value_name = "PATH", num_args = 0..=1, default_missing_value = "config/tcb-pins.json")]
    check_tcb_pins: Option<String>,

    /// Print resolved runtime configuration (non-secret keys only).
    #[arg(long)]
    print_config: bool,

    /// Start supervised pool + runtime controls (run-engine parity).
    #[arg(long)]
    run: bool,

    /// Working directory for `.env` files.
    #[arg(long, default_value = ".")]
    cwd: String,
}

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    if let Some(path) = cli.check_tcb_pins {
        if let Err(err) = run_check_tcb_pins(&path) {
            eprintln!("tcb-pins check failed: {err}");
            std::process::exit(1);
        }
        println!("tcb-pins OK: {path}");
        return;
    }

    let mut env = env_map_from_process();
    load_engine_env_files(&cli.cwd, &mut env);
    configure_event_log_from_env(&env);

    if cli.print_config {
        print_config(&env);
        return;
    }

    if cli.run {
        eprintln!(
            "[inference-engine] --run enter version={VERSION} cwd={}",
            cli.cwd
        );
        if let Err(err) = run_engine(&cli.cwd, &env).await {
            eprintln!("[inference-engine] --run failed: {err}");
            std::process::exit(1);
        }
        return;
    }

    println!("teechat-inference-engine {VERSION}");
    println!("Use --run to start the supervised pool, or --help.");
}

fn run_check_tcb_pins(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let pins = load_tcb_pins(path)?;
    let validated = validate_tcb_pins(&pins)?;
    println!("schema: {}", validated.schema);
    println!(
        "ope: version={} libope_ffi_sha256={}",
        validated.ope_version, validated.ope_ffi_sha256
    );
    println!(
        "attested_mtls: version={} lib_attested_mtls_sha256={}",
        validated.attested_mtls_version, validated.attested_mtls_sha256
    );
    Ok(())
}

fn print_config(env: &HashMap<String, String>) {
    let keys = [
        "TEECHAT_ENGINE_ID",
        "TEECHAT_OPE_ENGINE_ID",
        "TEECHAT_GATEWAY_ENGINE_PLANE_URL",
        "TEECHAT_ENGINE_GATEWAY_URL",
        "TEECHAT_ENGINE_POOL_TARGET_SIZE",
        "TEECHAT_ENGINE_POOL_BASELINE",
        "TEECHAT_ENGINE_POOL_INITIAL_FRACTION",
        "TEECHAT_VLLM_BASE_URL",
        "TEECHAT_EMBEDDINGS_UPSTREAM_URL",
        "TEECHAT_EMBED_MODEL",
        "VLLM_TASK_BASE_URL",
        "TEECHAT_TASK_MODEL",
        "TEECHAT_BUILD",
        "TEECHAT_ENGINE_SLOT",
        "TEECHAT_ENGINE_STUB",
        "TEECHAT_ENGINE_VERIFY_GATEWAY_PLATFORM",
        "OLLAMA_MODEL",
    ];
    for key in keys {
        if let Some(v) = env.get(key) {
            println!("{key}={v}");
        }
    }
    let _ = max_tokens_from_env(env);
    let _ = open_ai_chat_completions_url(
        env.get("TEECHAT_VLLM_BASE_URL")
            .or_else(|| env.get("VLLM_BASE_URL"))
            .map(String::as_str)
            .unwrap_or("http://127.0.0.1:11434/v1"),
    );
}

fn env_flag_true(env: &HashMap<String, String>, key: &str) -> bool {
    env.get(key)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn env_flag_false(env: &HashMap<String, String>, key: &str) -> bool {
    env.get(key)
        .map(|v| v == "0" || v.eq_ignore_ascii_case("false"))
        .unwrap_or(false)
}

fn verify_gateway_platform_enabled(env: &HashMap<String, String>) -> bool {
    // Default ON (fail-closed SEC-029). Opt out only with =0/false.
    !env_flag_false(env, "TEECHAT_ENGINE_VERIFY_GATEWAY_PLATFORM")
}

fn models_from_env(env: &HashMap<String, String>) -> Vec<String> {
    let mut models = env
        .get("OLLAMA_MODEL")
        .or_else(|| env.get("TEECHAT_OLLAMA_MODEL"))
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| vec![s.to_string()])
        .unwrap_or_else(|| vec!["google/gemma-4-31B-it".into()]);
    // Advertise the task model so gateway probes / titles / search prep can route via engine pool.
    if let Some(task) = task_model_id_from_env(env) {
        if !models.iter().any(|m| m == &task) {
            models.push(task);
        }
    }
    // Advertise the embeddings model so gateway OPE inventory can route /v1/embeddings.
    if let Some(embed) = embed_model_id_from_env(env) {
        if !models.iter().any(|m| m == &embed) {
            models.push(embed);
        }
    }
    models
}

fn clone_inference_options(template: &OpeInferenceOptions) -> OpeInferenceOptions {
    OpeInferenceOptions {
        request_id: None,
        decrypt_handle: template.decrypt_handle,
        rotating: template.rotating.clone(),
        provider: Arc::clone(&template.provider),
        vllm_base_url: template.vllm_base_url.clone(),
        vllm_api_key: template.vllm_api_key.clone(),
        task_vllm_base_url: template.task_vllm_base_url.clone(),
        task_vllm_api_key: template.task_vllm_api_key.clone(),
        task_model_id: template.task_model_id.clone(),
        embeddings_base_url: template.embeddings_base_url.clone(),
        embeddings_api_key: template.embeddings_api_key.clone(),
        embeddings_default_model: template.embeddings_default_model.clone(),
        vllm: VllmChatClient::default(),
        chunk_chars: template.chunk_chars,
        kv: template.kv.clone(),
        usage_signing_key: template.usage_signing_key.clone(),
        admitter: template.admitter.clone(),
    }
}

fn make_pull_worker_start_fn(
    h2: Arc<Http2EnginePlaneConnector>,
    inference_template: OpeInferenceOptions,
    on_desired: DesiredPoolTargetCallback,
    answer_challenge: EngineChallengeHandler,
    answer_ops_control: EngineOpsControlHandler,
    pool: Arc<SupervisedPool>,
) -> PullWorkerStartFn {
    Arc::new(move |session_id: String| {
        let h2 = Arc::clone(&h2);
        let inference = clone_inference_options(&inference_template);
        let on_desired = Arc::clone(&on_desired);
        let answer_challenge = Arc::clone(&answer_challenge);
        let answer_ops_control = Arc::clone(&answer_ops_control);
        let pool = Arc::clone(&pool);
        Box::pin(async move {
            let transport = h2
                .transport(&session_id)
                .await
                .ok_or_else(|| format!("missing transport for session {session_id}"))?;
            let on_lost = {
                let pool = Arc::clone(&pool);
                Arc::new(move |sid: String| {
                    pool.notify_transport_lost(sid);
                })
            };
            Ok(start_pull_worker(
                transport,
                session_id,
                inference,
                Some(on_desired),
                Some(answer_challenge),
                Some(answer_ops_control),
                Some(on_lost),
            ))
        })
    })
}

fn make_engine_challenge_handler(
    rotator: Arc<EpochRotator>,
    env: HashMap<String, String>,
    engine_id: String,
) -> EngineChallengeHandler {
    Arc::new(move |request| {
        let rotator = Arc::clone(&rotator);
        let env = env.clone();
        let engine_id = engine_id.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let epoch = EngineChallengeEpoch::from(&rotator.current_epoch());
                let attestation = rotator
                    .current_attestation()
                    .ok_or_else(|| "challenge_attestation_unavailable".to_string())?;
                let launch_digest = env
                    .get("TEECHAT_ENGINE_LAUNCH_DIGEST")
                    .map(|value| value.trim())
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| "")
                    .to_string();
                let launch_digest = if launch_digest.is_empty() {
                    "0".repeat(64)
                } else {
                    launch_digest
                };
                let image_digest = env
                    .get("TEECHAT_ENGINE_IMAGE_DIGEST")
                    .map(|value| value.trim())
                    .filter(|value| !value.is_empty())
                    .map(str::to_string)
                    .unwrap_or_else(|| "0".repeat(64));
                let policy_hash = env
                    .get("TEECHAT_ENGINE_POLICY_HASH")
                    .map(|value| value.trim())
                    .filter(|value| !value.is_empty())
                    .map(str::to_string)
                    .unwrap_or_else(|| {
                        if attestation.cpu_tee.policy_id.len() == 64 {
                            attestation.cpu_tee.policy_id.clone()
                        } else {
                            "0".repeat(64)
                        }
                    });
                let measurement = EngineChallengeMeasurement::LaunchDigest {
                    launch_digest,
                    image_digest,
                };
                mint_engine_challenge_response(&MintEngineChallengeArgs {
                    request: &request,
                    engine_id: &engine_id,
                    build_version: &attestation.engine.version,
                    policy_hash_hex: &policy_hash,
                    measurement: &measurement,
                    epoch: &epoch,
                    gpu_evidence_b64: Some(&attestation.gpu_tee.evidence),
                    gpu_collected_at: None,
                    env: &env,
                })
                .map_err(|error| error.to_string())
            })
            .await
            .map_err(|error| format!("challenge_mint_join: {error}"))?
        })
    })
}

fn make_engine_ops_control_handler(
    pool: Arc<SupervisedPool>,
    engine_id: String,
    rate: Arc<OpsControlRateLimiter>,
) -> EngineOpsControlHandler {
    Arc::new(move |request| {
        let pool = Arc::clone(&pool);
        let engine_id = engine_id.clone();
        let rate = Arc::clone(&rate);
        Box::pin(async move {
            if let Err(error) = rate.check(request.op).await {
                return ie_protocol::EngineOpsControlResult {
                    ok: false,
                    op: request.op,
                    engine_id,
                    pool_target: None,
                    live_sessions: Some(pool.live_session_count().await),
                    draining: None,
                    detail: None,
                    error: Some(error.to_string()),
                };
            }
            apply_engine_ops_control(&pool, &engine_id, request).await
        })
    })
}

struct StubConnector;

#[async_trait]
impl ie_engine::EnginePlaneConnector for StubConnector {
    async fn connect(
        &self,
        request: AttestedConnectRequest,
    ) -> Result<ie_engine::ConnectResult, Box<dyn std::error::Error + Send + Sync>> {
        Ok(ie_engine::ConnectResult {
            session_id: if request.session_id.is_empty() {
                Uuid::new_v4().to_string()
            } else {
                request.session_id
            },
            response: ie_protocol::AttestedConnectResponse {
                ok: true,
                gateway_attestation: None,
                pool_target_ack: Some(1),
                gateway_challenge_nonce: request.gateway_challenge_nonce,
            },
        })
    }

    async fn disconnect(
        &self,
        _session_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
}

struct StubUpstream {
    base_url: String,
}

#[async_trait]
impl ie_engine::InferenceUpstream for StubUpstream {
    async fn infer_chat(
        &self,
        model: &str,
        prompt: &str,
    ) -> Result<ie_engine::InferResult, Box<dyn std::error::Error + Send + Sync>> {
        Ok(ie_engine::InferResult {
            completion: format!("stub:{model}:{prompt} @ {}", self.base_url),
            finish_reason: Some("stop".into()),
        })
    }
}

struct ConnectorPoster {
    connector: Arc<Http2EnginePlaneConnector>,
}

#[async_trait]
impl EphemeralPoster for ConnectorPoster {
    async fn post_ephemeral(
        &self,
        session_id: &str,
        body: &EngineEphemeralRegisterRequest,
    ) -> Result<u16, String> {
        self.connector.post_ephemeral(session_id, body).await
    }
}

async fn run_engine(
    cwd: &str,
    env: &HashMap<String, String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let tcb_path = std::path::Path::new(cwd).join("config/tcb-pins.json");
    if tcb_path.exists() {
        validate_tcb_pins(&load_tcb_pins(tcb_path.to_string_lossy().as_ref())?)?;
    }

    let engine_id = env
        .get("TEECHAT_OPE_ENGINE_ID")
        .or_else(|| env.get("TEECHAT_ENGINE_ID"))
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("engine-rust-canary")
        .to_string();

    let gateway = env
        .get("TEECHAT_ENGINE_GATEWAY_URL")
        .or_else(|| env.get("TEECHAT_GATEWAY_ENGINE_PLANE_URL"))
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("https://127.0.0.1:8788")
        .to_string();

    let pool_target_size = env
        .get("TEECHAT_ENGINE_POOL_TARGET_SIZE")
        .or_else(|| env.get("TEECHAT_OPE_ENGINE_POOL_TARGET_SIZE"))
        .and_then(|v| v.parse().ok())
        .unwrap_or(1)
        .max(1);

    let upstream_base = env
        .get("TEECHAT_VLLM_BASE_URL")
        .or_else(|| env.get("VLLM_BASE_URL"))
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("http://127.0.0.1:11434/v1")
        .to_string();

    let models = models_from_env(env);
    let force_stub = env_flag_true(env, "TEECHAT_ENGINE_STUB");
    let instance_id = engine_instance_id_from_env(env)?;
    eprintln!(
        "[inference-engine] --run config engine_id={engine_id} gateway={gateway} stub={force_stub} pool={pool_target_size} upstream={upstream_base}"
    );

    if env_flag_false(env, "TEECHAT_ENGINE_TLS_REJECT_UNAUTHORIZED") && !force_stub {
        return Err(
            "TEECHAT_ENGINE_TLS_REJECT_UNAUTHORIZED=0 is forbidden; use TEECHAT_ENGINE_STUB=1 for local stubs"
                .into(),
        );
    }

    let prefer_mock = env
        .get("TEECHAT_CRYPTO")
        .map(|v| v.eq_ignore_ascii_case("mock"))
        .unwrap_or(false)
        || force_stub;

    let provider: Arc<dyn ie_crypto::CryptoProvider> = if prefer_mock {
        Arc::new(MockCryptoProvider::new())
    } else {
        Arc::new(RealCryptoProvider::new())
    };

    let (signing_key, ed25519_public_b64) = if force_stub {
        let kp = mock_keypair_from_seed(&DEV_VECTOR_001_SEED);
        (kp.secret.clone(), encode(kp.public.to_bytes().as_slice()))
    } else {
        let signing_key = SigningKey::generate(&mut OsRng);
        let ed25519_public_b64 = encode(signing_key.verifying_key().as_bytes());
        (signing_key, ed25519_public_b64)
    };

    // Minted once and reused below. The digest goes into REPORT_DATA and the
    // gateway checks it against the certificate this process actually presents,
    // so a second call here would mint a second key and break that binding.
    let engine_plane_tls = if force_stub {
        None
    } else {
        Some(engine_plane_client_tls(env, &engine_id).map_err(|e| {
            format!("TLS material required for live H2 (or set TEECHAT_ENGINE_STUB=1): {e}")
        })?)
    };

    let tls_cert_sha = match &engine_plane_tls {
        Some(tls) => tls.client_cert_sha256.clone(),
        None => "0".repeat(64),
    };
    eprintln!(
        "[inference-engine] tls material ready stub={force_stub} cert_sha={:.16}…",
        tls_cert_sha
    );

    eprintln!("[inference-engine] building attestation bundle (snp+gpu)…");
    let attestation = build_engine_attestation_bundle(
        env,
        Path::new(cwd),
        &ed25519_public_b64,
        &tls_cert_sha,
        None,
    )?;
    eprintln!("[inference-engine] attestation ready; dialing {gateway}");

    let challenge = generate_gateway_connect_challenge_nonce();
    let connect = AttestedConnectRequest {
        session_id: Uuid::new_v4().to_string(),
        engine_id: engine_id.clone(),
        models: models.clone(),
        identity: ie_protocol::EngineStartupIdentity {
            engine_id: engine_id.clone(),
            kex: "X25519MLKEM768".into(),
            ed25519_public: ed25519_public_b64.clone(),
        },
        attestation: attestation.clone(),
        pool_target_size: Some(pool_target_size),
        instance_id: Some(instance_id.clone()),
        gateway_challenge_nonce: Some(challenge.clone()),
        // Phase 2a: advertise ops_control_v1 only with pull handler wired below.
        capabilities: Some(vec![CAPABILITY_OPS_CONTROL_V1.to_string()]),
    };

    type LivePlane = (
        Arc<dyn ie_engine::EnginePlaneConnector>,
        Arc<dyn ie_engine::InferenceUpstream>,
        Option<Arc<Http2EnginePlaneConnector>>,
    );
    let (connector, upstream, h2): LivePlane = if force_stub {
        (
            Arc::new(StubConnector),
            Arc::new(StubUpstream {
                base_url: upstream_base.clone(),
            }),
            None,
        )
    } else {
        let tls = engine_plane_tls
            .clone()
            .ok_or_else(|| "TLS material required for live H2".to_string())?;
        let verifier: Option<Arc<dyn ie_engine::GatewayAttestationVerifier>> =
            if verify_gateway_platform_enabled(env) {
                Some(Arc::new(platform_policy_verifier_from_env(env)))
            } else {
                eprintln!(
                    "[inference-engine] WARNING: TEECHAT_ENGINE_VERIFY_GATEWAY_PLATFORM=0 — SEC-029 verify disabled"
                );
                None
            };
        let dial = EnginePlaneDialOptions {
            gateway_base_url: gateway.clone(),
            tls,
            reject_unauthorized: true,
            connect_template: connect.clone(),
            pool_target_size,
            gateway_challenge_nonce: Some(challenge),
            gateway_verifier: verifier,
        };
        let h2 = Arc::new(Http2EnginePlaneConnector::new(dial));
        (
            h2.clone() as Arc<dyn ie_engine::EnginePlaneConnector>,
            Arc::new(VllmChatClient::default()),
            Some(h2),
        )
    };

    let mut pool_config = SupervisedPoolConfig::from_env(env);
    // Keep dial-time target and supervised config aligned (OPE_ / ENGINE_ aliases).
    pool_config.pool_target_size = pool_target_size;

    let pool = Arc::new(
        SupervisedPool::new(pool_config.clone(), gateway.clone(), connector, upstream)
            .with_connect_throttle(create_pool_connect_throttle_from_env(env, pool_target_size)),
    );

    let live_sessions: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let mut rotator_handle: Option<Arc<EpochRotator>> = None;
    let mut prune_task: Option<tokio::task::JoinHandle<()>> = None;

    if let Some(h2) = h2 {
        pool.set_on_sessions_changed(Some(Arc::new({
            let live = Arc::clone(&live_sessions);
            move |ids: Vec<String>| {
                *live.lock().expect("sessions") = ids;
            }
        })))
        .await;

        let list_sessions = {
            let live = Arc::clone(&live_sessions);
            Arc::new(move || {
                live.lock()
                    .expect("sessions")
                    .iter()
                    .map(|id| EpochRotatorSession {
                        session_id: id.clone(),
                    })
                    .collect()
            })
        };
        let poster: Arc<dyn EphemeralPoster> = Arc::new(ConnectorPoster {
            connector: Arc::clone(&h2),
        });
        let decryptor_cell: Arc<Mutex<Option<Arc<RotatingEpochDecryptor>>>> =
            Arc::new(Mutex::new(None));
        let cell_for_cb = Arc::clone(&decryptor_cell);
        let on_rotated: EpochRotatedCallback = Arc::new(move |epoch, _prev| {
            if let Some(d) = cell_for_cb.lock().expect("decryptor cell").as_ref() {
                d.add_epoch(epoch.clone());
            }
        });

        // Every epoch gets its own hardware report over its own keys. When the
        // platform cannot produce one, the rotator falls back to the connect
        // bundle so a mock/dev boot still comes up (RB-45).
        let mint_epoch_evidence: EpochEvidenceMinter = {
            let ed25519_public = ed25519_public_b64.clone();
            let tls_cert_sha = tls_cert_sha.clone();
            let root = PathBuf::from(cwd);
            let env = env.clone();
            Arc::new(move |claims: &QuoteEpochClaims| {
                match build_engine_epoch_attestation_bundle(
                    &env,
                    &root,
                    &ed25519_public,
                    &tls_cert_sha,
                    claims,
                    None,
                ) {
                    Ok(bundle) => Some(bundle),
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            epoch_id = %claims.epoch_id,
                            "per-epoch attestation unavailable; falling back to connect evidence"
                        );
                        None
                    }
                }
            })
        };

        let rotator = Arc::new(EpochRotator::new(EpochRotatorOptions {
            engine_id: engine_id.clone(),
            ed25519_public_b64: ed25519_public_b64.clone(),
            signing_key: signing_key.clone(),
            provider: Arc::clone(&provider),
            attestation: Some(attestation),
            mint_epoch_evidence: Some(mint_epoch_evidence),
            env,
            list_sessions,
            poster,
            on_epoch_rotated: Some(on_rotated),
        })?);
        let decryptor = Arc::new(RotatingEpochDecryptor::new(
            rotator.current_epoch(),
            epoch_rotation_policy_from_env(env).overlap_grace_ms,
        ));
        *decryptor_cell.lock().expect("decryptor cell") = Some(Arc::clone(&decryptor));

        // Remint attestation on later scale/migrate (parity with TS applyFreshAttestation).
        let refresh_inner = create_engine_attestation_refresher(EngineAttestationRefreshContext {
            ed25519_public: ed25519_public_b64.clone(),
            tls_client_cert_sha256: tls_cert_sha.clone(),
            root: PathBuf::from(cwd),
            env: env.clone(),
        });
        let rotator_for_refresh = Arc::clone(&rotator);
        pool.set_attestation_refresh(Some(Arc::new(move || {
            let bundle = refresh_inner().map_err(|e| e.to_string())?;
            rotator_for_refresh.set_attestation(bundle.clone());
            Ok(bundle)
        })))
        .await;

        let shared_kv = Arc::new(Mutex::new(HashMap::new()));
        let (embeddings_base_url, embeddings_api_key) = match embeddings_config_from_env(env) {
            Some((url, key)) => (Some(url), key),
            None => (None, None),
        };
        let (task_vllm_base_url, task_vllm_api_key) = match vllm_task_config_from_env(env) {
            Some((url, key)) => (Some(url), key),
            None => (None, None),
        };
        let inference_template = OpeInferenceOptions {
            request_id: None,
            decrypt_handle: 0,
            rotating: Some(Arc::clone(&decryptor)),
            provider: Arc::clone(&provider),
            vllm_base_url: upstream_base.clone(),
            vllm_api_key: env.get("VLLM_API_KEY").cloned(),
            task_vllm_base_url,
            task_vllm_api_key,
            task_model_id: task_model_id_from_env(env),
            embeddings_base_url,
            embeddings_api_key,
            embeddings_default_model: embed_model_id_from_env(env),
            vllm: VllmChatClient::default(),
            chunk_chars: env
                .get("TEECHAT_ENGINE_CHUNK_CHARS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(8),
            kv: Some(Arc::clone(&shared_kv)),
            usage_signing_key: Some(signing_key),
            admitter: match ie_crypto::EnvelopeAdmitter::from_env(env) {
                Ok(Some(a)) => {
                    tracing::info!(
                        mode = ?a.mode(),
                        "RB-05 envelope admission enabled"
                    );
                    let arc = Arc::new(a);
                    ie_crypto::install_global_admitter(Some(Arc::clone(&arc)));
                    Some(arc)
                }
                Ok(None) => {
                    tracing::info!("RB-05 envelope admission off (no trust keys / VERIFY=off)");
                    None
                }
                Err(e) => {
                    tracing::error!(error = %e, "RB-05 envelope admission config invalid");
                    return Err(e.to_string().into());
                }
            },
        };

        let on_desired = spawn_desired_pool_applier(Arc::clone(&pool), pool_config.clone());
        let answer_challenge =
            make_engine_challenge_handler(Arc::clone(&rotator), env.clone(), engine_id.clone());
        let answer_ops_control = make_engine_ops_control_handler(
            Arc::clone(&pool),
            engine_id.clone(),
            Arc::new(OpsControlRateLimiter::default_prod()),
        );
        pool.set_on_session_ready(Some({
            let rotator = Arc::clone(&rotator);
            Arc::new(move |session_id: String| {
                let rotator = Arc::clone(&rotator);
                Box::pin(async move {
                    rotator
                        .register_epoch_on_session(&session_id)
                        .await
                        .map_err(|e| e.to_string())
                })
            })
        }))
        .await;
        pool.set_pull_worker_start_fn(Some(make_pull_worker_start_fn(
            Arc::clone(&h2),
            inference_template,
            on_desired,
            answer_challenge,
            answer_ops_control,
            Arc::clone(&pool),
        )))
        .await;

        // Boot after starter is installed so scale/ops paths share the same worker lifecycle.
        pool.boot(connect).await?;

        // Zero-boot staging has no sessions yet — epoch lands on first scale (TS parity).
        if pool.live_session_count().await > 0 {
            rotator.register_initial_epoch().await?;
            // TS parity: start pull workers AFTER bulk epoch registration so the
            // long-poll never contends with the ephemeral epoch POST on the same H2 stream
            // (boot's `attachSlotCore` connects only; epoch registers, then pull workers start).
            for sid in pool.session_ids().await {
                if let Err(err) = pool.workers().ensure_started(&sid).await {
                    warn_pull_worker_start(&sid, &err);
                }
            }
        }
        rotator.start().await;
        pool.start_session_watch().await;
        rotator_handle = Some(Arc::clone(&rotator));

        // Drop retired epochs past overlap grace (TS `pruneTimer`, 60s).
        {
            let prune_decryptor = Arc::clone(&decryptor);
            prune_task = Some(tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(60));
                interval.tick().await; // skip immediate first tick
                loop {
                    interval.tick().await;
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(0);
                    prune_decryptor.prune_retired(now_ms, None);
                }
            }));
        }
    } else {
        pool.boot(connect).await?;
    }

    let _controls = install_engine_controls(Arc::clone(&pool), &engine_id, env).await?;

    let embeddings_log = embeddings_config_from_env(env)
        .map(|(url, _)| url)
        .unwrap_or_else(|| "-".into());
    println!(
        "[inference-engine] engine_id={engine_id} gateway={gateway} upstream={upstream_base} embeddings={embeddings_log} pool={pool_target_size} baseline={} models={} stub={force_stub}",
        pool_config.pool_baseline,
        models.join(",")
    );
    println!("[inference-engine] supervised pool running — Ctrl+C to stop");

    shutdown::wait_shutdown_signal().await;
    if let Some(task) = prune_task {
        task.abort();
    }
    if let Some(r) = rotator_handle {
        r.stop().await;
    }
    pool.close_all().await?;
    Ok(())
}
