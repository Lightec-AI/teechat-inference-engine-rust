# Porting map: TypeScript InferenceEngine → Rust workspace

Source of truth: `TeaChat/vendor/inference-engine` (~8.5k LOC TypeScript).

This document tracks what is ported in **teechat-inference-engine-rust** and what remains.

## Milestone checklist

| Milestone | Scope | Status |
|-----------|--------|--------|
| **M1** | `ope-stream` + `ie-crypto` decrypt/encrypt + golden tests | **Done** |
| **M2** | work-pull + OPE inference handler + vLLM SSE + mock H2 IT | **Done** |
| **M3** | supervised pool, epoch, drain/scale/status/migrate/cutover | **Done** |
| **M4** | SEV-SNP + NV-CC backends + policy/fixture tests | **Done** |
| **M5** | `ie-bin` run-engine parity + measured release packaging | **Done** |
| **M6** | staging smoke + `engine-rust-canary` install docs (**no prod install**) | **Done** — see [`CANARY.md`](CANARY.md) |
| **M7** | metering/prefill/ops leftovers + full test matrix vs TS `test/` | **Done** — see [`TEST_MATRIX.md`](TEST_MATRIX.md) |

Gate each milestone: `cargo test --workspace` + `cargo clippy --workspace --all-targets -- -D warnings`.

## Module mapping

| TypeScript | Rust | Status |
|------------|------|--------|
| `src/protocol/types.ts` | `crates/ie-protocol` | **Ported** |
| `src/protocol/ope-stream.ts` | `ie-protocol::ope_stream` | **Ported** |
| `src/sev-snp/measurements.ts` | `crates/ie-attestation/src/measurements.rs` | **Ported** |
| `src/sev-snp/build-attestation.ts` | `ie-attestation` bundle/claims | **Ported** |
| `src/sev-snp/guest-report.ts`, `quote.ts`, `verify-report.ts` | `ie-attestation::sev_snp` | **Ported** — hardware paths `#[ignore]` without device |
| `src/attestation.ts` | `ie-attestation` mock/policy/verify | **Ported** |
| `src/attestation-fixture-backend.ts` | `ie-attestation::fixture` | **Ported** |
| `src/nv-cc/*` | `ie-attestation::nv_cc` | **Ported** — claim validation + mock/fixture |
| `src/runtime/load-env.ts` | `crates/ie-runtime/src/env.rs` | **Ported** |
| `src/runtime/engine-tls.ts` | `crates/ie-runtime/src/tls.rs` | **Ported** |
| `src/native/ope-ffi.ts`, `src/crypto/provider.ts` | `crates/ie-crypto` | **Ported** |
| `src/engine-plane/pool-client.ts` | `crates/ie-engine/src/plane` | **Ported** — dial/connect/pull/result + H2 transport |
| `src/engine/gateway-connect-nonce.ts` | `ie-engine::plane::challenge` | **Ported** |
| `src/engine/supervised-pool.ts` | `crates/ie-engine/src/pool.rs` | **Ported** — drain/scale/migrate + controls |
| `src/engine/epoch*.ts`, `rotating-decryptor.ts` | `ie-engine::epoch` | **Ported** |
| `src/engine/pool-*.ts`, `gateway-migration*.ts` | `ie-engine::controls`, `cutover`, `gateway_migration` | **Ported** |
| `src/upstream/vllm-chat.ts` | `crates/ie-upstream` | **Ported** — POST + SSE + `InferenceUpstream` impl |
| `src/server/ope-inference.ts` | `ie-engine::infer` | **Ported** — decrypt → vLLM → encrypt + gate |
| `src/metering.ts`, `src/prefill.ts`, `src/ephemeral.ts` | `ie-engine::ops` | **Ported** |
| `src/engine/instance-id.ts` | `ie-engine::ops::instance_id` | **Ported** |
| `src/ops/event-log.ts` | `ie-engine::ops::event_log` | **Ported** (stub sink) |
| `scripts/run-engine.ts` | `crates/ie-bin --run` | **Ported** — supervised pool + controls |
| `scripts/pack-runtime.mjs` | `scripts/pack-runtime.sh` | **Ported** |

## Measurement semantics (must not regress)

1. **`engine.binary_sha256`** — InferenceEngine runtime bundle hash (`TEECHAT_IE_RUNTIME_SHA256` / `RELEASE_MANIFEST.json`). **Not** `libope_ffi.so`.
2. **`ope.libope_ffi_sha256`** — independent OPE FFI TCB from `config/tcb-pins.json` / env overrides.
3. **`attested_mtls.lib_attested_mtls_sha256`** — independent attested-mtls native library TCB.

## Explicit non-goals until M6 green

- No replace of `engine-prod-1` / no blue-green cutover of TS IE
- No TeeChat `minor-release` packaging of Rust IE
- No fail-closed client changes that require Rust-only claims
- Reserved canary id: `TEECHAT_OPE_ENGINE_ID=engine-rust-canary` — see [`CANARY.md`](CANARY.md)

## CLI parity

| TS (`run-engine.ts`) | Rust (`ie-bin`) |
|----------------------|-----------------|
| Start supervised pool + infer loop | `--run` |
| Load `.env` / staging | `--cwd` + `load_engine_env_files` |
| TCB pin validation (implicit on boot) | `--check-tcb-pins [path]` + boot validation |
| Pack runtime + manifest | `bash scripts/pack-runtime.sh` |
