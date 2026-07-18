use clap::Parser;
use ie_attestation::{load_tcb_pins, validate_tcb_pins};
use ie_runtime::{env_map_from_process, load_engine_env_files};
use tracing_subscriber::EnvFilter;

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

    /// Working directory for `.env` files (used with `--print-config`).
    #[arg(long, default_value = ".")]
    cwd: String,
}

fn main() {
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

    if cli.print_config {
        let mut env = env_map_from_process();
        load_engine_env_files(&cli.cwd, &mut env);
        let keys = [
            "TEECHAT_ENGINE_ID",
            "TEECHAT_GATEWAY_ENGINE_PLANE_URL",
            "TEECHAT_ENGINE_POOL_TARGET_SIZE",
            "TEECHAT_VLLM_BASE_URL",
            "TEECHAT_BUILD",
        ];
        for key in keys {
            if let Some(v) = env.get(key) {
                println!("{key}={v}");
            }
        }
        return;
    }

    println!("teechat-inference-engine {VERSION}");
    println!("Run with --help. Server loop not yet implemented — see docs/PORTING.md.");
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
