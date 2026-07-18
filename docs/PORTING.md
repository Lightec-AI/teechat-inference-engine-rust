# Porting map: TypeScript InferenceEngine → Rust workspace

Source of truth: `TeaChat/vendor/inference-engine` (~8.5k LOC TypeScript).

This document tracks what is ported in **teechat-inference-engine-rust** and what remains.

## Module mapping

| TypeScript | Rust | Status |
|------------|------|--------|
| `src/protocol/types.ts` | `crates/ie-protocol` | **Ported** — serde structs, headers, traffic class helpers |
| `src/protocol/ope-stream.ts` | `ie-protocol` (future) | TODO — streaming envelope chunk types |
| `src/sev-snp/measurements.ts` | `crates/ie-attestation/src/measurements.rs` | **Ported** — env/manifest/tcb-pins resolution; engine hash ≠ OPE FFI |
| `src/sev-snp/build-attestation.ts` | `crates/ie-attestation/src/bundle.rs`, `claims.rs` | **Partial** — claim/bundle builder; no guest report / NV-CC I/O |
| `src/sev-snp/guest-report.ts`, `quote.ts`, `verify-report.ts` | — | TODO — `/dev/sev-guest`, quote wrapper v2 |
| `src/attestation.ts` | `ie-attestation` (future) | TODO — policy verify, mock HMAC dev quotes |
| `src/nv-cc/*` | — | TODO — GPU attestation collect/verify |
| `src/runtime/load-env.ts` | `crates/ie-runtime/src/env.rs` | **Ported** |
| `src/runtime/engine-tls.ts` | `crates/ie-runtime/src/tls.rs` | **Ported** — via `attested-mtls` |
| `src/native/ope-ffi.ts`, `src/crypto/provider.ts` | `crates/ie-crypto` | **Partial** — crate wrappers; no FFI load path yet |
| `src/engine/supervised-pool.ts` | `crates/ie-engine` | **Partial** — config, traits, pool skeleton + tests |
| `src/engine/epoch*.ts`, `rotating-decryptor.ts` | — | TODO |
| `src/engine/pool-*.ts`, `gateway-migration*.ts` | — | TODO |
| `src/engine-plane/pool-client.ts` | `ie-engine::EnginePlaneConnector` trait | TODO — HTTP/2 attested TLS dial |
| `src/upstream/vllm-chat.ts` | `crates/ie-upstream` | **Partial** — POST + SSE stream skeleton, body builders |
| `src/server/ope-inference.ts` | — | TODO — decrypt → vLLM → encrypt handler |
| `src/metering.ts`, `src/prefill.ts` | — | TODO |
| `scripts/run-engine.ts` | `crates/ie-bin` | **Partial** — CLI only (`--check-tcb-pins`, `--config`) |
| `config/tcb-pins.json` | `config/tcb-pins.json` | **Copied** |

## Measurement semantics (must not regress)

1. **`engine.binary_sha256`** — InferenceEngine runtime bundle hash (`TEECHAT_IE_RUNTIME_SHA256` / `RELEASE_MANIFEST.json`). **Not** `libope_ffi.so`.
2. **`ope.libope_ffi_sha256`** — independent OPE FFI TCB from `config/tcb-pins.json` / env overrides.
3. **`attested_mtls.lib_attested_mtls_sha256`** — independent attested-mtls native library TCB.

## Remaining work (priority)

1. **Engine-plane HTTP/2 client** — attested TLS connect/disconnect/work-pull (`pool-client.ts`).
2. **OPE inference path** — wire `ope-e2e` decrypt + response encrypt in a Tokio handler.
3. **SEV-SNP production backend** — guest report + quote wrapper encoding.
4. **Attestation verification** — policy file, GPU NV-CC, gateway platform verify.
5. **Supervised pool parity** — epoch rotation, reconnect attestation refresh, blue/green cutover.
6. **Integration tests** — golden vectors from TS `test/` against Rust crates.
7. **Runtime packaging** — RELEASE_MANIFEST, native `.so` fetch scripts mirroring TS `scripts/`.

## CLI parity

| TS (`run-engine.ts`) | Rust (`ie-bin`) |
|----------------------|-----------------|
| Start supervised pool + infer loop | Not yet |
| Load `.env` / staging | `--config` prints selected keys |
| TCB pin validation (implicit on boot) | `--check-tcb-pins [path]` |
