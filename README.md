# TeeChat InferenceEngine (Rust)

Rust rewrite of [`@teechat/inference-engine`](https://github.com/Lightec-AI/InferenceEngine) — decrypts OPE envelopes, manages the attested engine-plane pool, calls vLLM, and builds SEV-SNP attestation bundles.

**Milestones M1–M7 are Done** (see [`docs/PORTING.md`](docs/PORTING.md)). Wire protocol types should stay aligned with TeaChat’s `@teechat/ope-protocol` (OPE package); this repo keeps a Rust `ie-protocol` mirror.

## Workspace layout

| Crate | Role |
|-------|------|
| `ie-protocol` | Gateway ↔ engine HTTP contract + OPE stream codec |
| `ie-crypto` | OPE E2E / envelope wrappers |
| `ie-attestation` | Measurements, SNP/NV-CC, platform SEC-029 verify, attestation refresh |
| `ie-engine` | Supervised pool, epoch, pull/infer, drain/scale/migrate |
| `ie-upstream` | OpenAI-compatible vLLM client + multimodal normalize |
| `ie-runtime` | Env load + attested-mtls TLS |
| `ie-bin` | `teechat-inference-engine` CLI (`--run`) |

## Dependencies

Pinned third-party TCB crates (crates.io):

- `attested-mtls` 0.1.0 — engine-plane TLS material
- `ope-crypto`, `ope-envelope`, `ope-transport`, `ope-e2e` 0.1.0 — hybrid PQ E2E

Native `.so` hashes are pinned in [`config/tcb-pins.json`](config/tcb-pins.json).

## Build

Requires **Rust 1.88** (see `rust-toolchain.toml`).

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p ie-bin -- --check-tcb-pins
cargo run -p ie-bin -- --run
```

## Status

Capable of supervised pool boot, work-pull OPE inference, epoch rotation, attestation remint on scale/migrate, and SEC-029 gateway platform verify (env-gated). Staging canary: [`docs/CANARY.md`](docs/CANARY.md).

### Explicit non-goals (until TeaChat ops asks)

- No replace of `engine-prod-1` / no production blue-green cutover
- No TeeChat `minor-release` packaging of Rust IE as default prod engine

## License

Apache-2.0
