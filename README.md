# TeeChat InferenceEngine (Rust)

Rust rewrite of [`@teechat/inference-engine`](https://github.com/Lightec-AI/TeaChat/tree/main/vendor/inference-engine) — the TeeChat control plane that decrypts OPE envelopes, manages the attested engine-plane pool, calls vLLM, and builds SEV-SNP attestation bundles.

This repository tracks the TypeScript InferenceEngine **alongside** the monorepo vendor package. Behavior source of truth remains the TS tree until parity tests land here.

## Workspace layout

| Crate | Role |
|-------|------|
| `ie-protocol` | Gateway ↔ engine HTTP contract (`protocol/types.ts`) |
| `ie-crypto` | OPE E2E / envelope wrappers (`ope-*` crates) |
| `ie-attestation` | Measurements + claim structs (`sev-snp/measurements.ts`, `build-attestation.ts`) |
| `ie-engine` | Supervised pool skeleton (`engine/supervised-pool.ts`) |
| `ie-upstream` | OpenAI-compatible vLLM client (`upstream/vllm-chat.ts`) |
| `ie-runtime` | Env load + attested-mtls TLS (`runtime/load-env.ts`, `engine-tls.ts`) |
| `ie-bin` | `teechat-inference-engine` CLI entrypoint |

## Dependencies

Pinned third-party TCB crates (crates.io):

- `attested-mtls` 0.1.0 — engine-plane TLS material
- `ope-crypto`, `ope-envelope`, `ope-transport`, `ope-e2e` 0.1.0 — hybrid PQ E2E

Native `.so` hashes are pinned in [`config/tcb-pins.json`](config/tcb-pins.json) (copied from InferenceEngine).

## Build

Requires **Rust 1.88** (see `rust-toolchain.toml`).

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p ie-bin -- --check-tcb-pins
```

## Status

First-cut port: protocol types, measurement resolution, attestation claim builders, vLLM SSE client skeleton, supervised pool traits, env/TLS loaders, and TCB pin validation.

Not yet implemented: HTTP/2 engine-plane server loop, OPE decrypt/infer handler, SEV-SNP guest report I/O, NV-CC GPU evidence, epoch rotation, gateway migration/cutover, metering, and production attestation verification. See [`docs/PORTING.md`](docs/PORTING.md).

## License

Apache-2.0
