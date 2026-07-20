use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use clap::Parser;
use ed25519_dalek::SigningKey;
use ie_attestation::{
    build_engine_attestation_bundle, load_tcb_pins, validate_tcb_pins,
};
use ie_crypto::{MockCryptoProvider, RealCryptoProvider};
use ie_engine::{
    configure_event_log_from_env, engine_instance_id_from_env, epoch_rotation_policy_from_env,
    generate_gateway_connect_challenge_nonce, install_engine_controls, start_pull_worker,
    EnginePlaneDialOptions, EphemeralPoster, EpochRotatedCallback, EpochRotator, EpochRotatorSession,
    Http2EnginePlaneConnector, NonceEchoGatewayAttestationVerifier, OpeInferenceOptions,
    PullWorkerHandle, RotatingEpochDecryptor, SupervisedPool, SupervisedPoolConfig,
};
use ie_protocol::{AttestedConnectRequest, EngineEphemeralRegisterRequest};
use ie_runtime::{env_map_from_process, load_engine_env_files, load_engine_plane_client_tls};
use ie_upstream::{max_tokens_from_env, open_ai_chat_completions_url, VllmChatClient};
use ope_crypto::{encode, mock_keypair_from_seed, DEV_VECTOR_001_SEED};
use rand::rngs::OsRng;
use tokio::signal;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

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
        if let Err(err) = run_engine(&cli.cwd, &env).await {
            eprintln!("engine failed: {err}");
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
        "TEECHAT_VLLM_BASE_URL",
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
    env.get("OLLAMA_MODEL")
        .or_else(|| env.get("TEECHAT_OLLAMA_MODEL"))
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| vec![s.to_string()])
        .unwrap_or_else(|| vec!["google/gemma-4-31B-it".into()])
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
        (
            kp.secret.clone(),
            encode(kp.public.to_bytes().as_slice()),
        )
    } else {
        let signing_key = SigningKey::generate(&mut OsRng);
        let ed25519_public_b64 = encode(signing_key.verifying_key().as_bytes());
        (signing_key, ed25519_public_b64)
    };

    let tls_cert_sha = if force_stub {
        "0".repeat(64)
    } else {
        load_engine_plane_client_tls(env)
            .map_err(|e| {
                format!("TLS material required for live H2 (or set TEECHAT_ENGINE_STUB=1): {e}")
            })?
            .client_cert_sha256
    };

    let attestation = build_engine_attestation_bundle(
        env,
        Path::new(cwd),
        &ed25519_public_b64,
        &tls_cert_sha,
        None,
    )?;

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
        let tls = load_engine_plane_client_tls(env).map_err(|e| {
            format!("TLS material required for live H2 (or set TEECHAT_ENGINE_STUB=1): {e}")
        })?;
        let verifier: Option<Arc<dyn ie_engine::GatewayAttestationVerifier>> =
            if verify_gateway_platform_enabled(env) {
                Some(Arc::new(NonceEchoGatewayAttestationVerifier))
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

    let pool = Arc::new(SupervisedPool::new(
        SupervisedPoolConfig::from_env(env),
        gateway.clone(),
        connector,
        upstream,
    ));

    pool.boot(connect).await?;
    let session_ids = pool.session_ids().await;
    let live_sessions: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(session_ids.clone()));

    let mut pull_workers: Vec<PullWorkerHandle> = Vec::new();
    let mut rotator_handle: Option<Arc<EpochRotator>> = None;

    if let Some(h2) = h2 {
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

        let rotator = Arc::new(EpochRotator::new(
            engine_id.clone(),
            ed25519_public_b64.clone(),
            signing_key.clone(),
            Arc::clone(&provider),
            Some(attestation),
            env,
            list_sessions,
            poster,
            Some(on_rotated),
        )?);
        let decryptor = Arc::new(RotatingEpochDecryptor::new(
            rotator.current_epoch(),
            epoch_rotation_policy_from_env(env).overlap_grace_ms,
        ));
        *decryptor_cell.lock().expect("decryptor cell") = Some(Arc::clone(&decryptor));

        rotator.register_initial_epoch().await?;
        rotator.start().await;
        rotator_handle = Some(Arc::clone(&rotator));

        let inference_template = OpeInferenceOptions {
            request_id: None,
            decrypt_handle: 0,
            rotating: Some(Arc::clone(&decryptor)),
            provider: Arc::clone(&provider),
            vllm_base_url: upstream_base.clone(),
            vllm_api_key: env.get("VLLM_API_KEY").cloned(),
            vllm: VllmChatClient::default(),
            chunk_chars: env
                .get("TEECHAT_ENGINE_CHUNK_CHARS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(8),
            kv: Some(Mutex::new(HashMap::new())),
            usage_signing_key: Some(signing_key),
        };

        for sid in session_ids {
            let transport = h2
                .transport(&sid)
                .await
                .ok_or_else(|| format!("missing transport for session {sid}"))?;
            pull_workers.push(start_pull_worker(
                transport,
                sid,
                OpeInferenceOptions {
                    request_id: None,
                    decrypt_handle: 0,
                    rotating: inference_template.rotating.clone(),
                    provider: Arc::clone(&inference_template.provider),
                    vllm_base_url: inference_template.vllm_base_url.clone(),
                    vllm_api_key: inference_template.vllm_api_key.clone(),
                    vllm: VllmChatClient::default(),
                    chunk_chars: inference_template.chunk_chars,
                    kv: None,
                    usage_signing_key: inference_template.usage_signing_key.clone(),
                },
            ));
        }
    }

    let _controls = install_engine_controls(Arc::clone(&pool), &engine_id, env).await?;

    println!(
        "[inference-engine] engine_id={engine_id} gateway={gateway} upstream={upstream_base} pool={pool_target_size} models={} stub={force_stub}",
        models.join(",")
    );
    println!("[inference-engine] supervised pool running — Ctrl+C to stop");

    signal::ctrl_c().await?;
    for w in pull_workers {
        w.stop();
    }
    if let Some(r) = rotator_handle {
        r.stop().await;
    }
    pool.close_all().await?;
    Ok(())
}
