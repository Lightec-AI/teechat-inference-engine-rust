# TeeChat InferenceEngine (Rust)

**Production InferenceEngine train** for TeeChat. Decrypts OPE envelopes, manages the attested engine-plane pool, calls vLLM, and builds SEV-SNP attestation bundles.

The TypeScript repo [`Lightec-AI/InferenceEngine`](https://github.com/Lightec-AI/InferenceEngine) is **archived** — new metering, signing, and runtime work lands here. Wire protocol types stay aligned with TeaChat’s `@teechat/ope-protocol` / OPE `ope-protocol` (Rust SoT); this repo re-exports via `ie-protocol`.

**Milestones M1–M7 are Done** (see [`docs/PORTING.md`](docs/PORTING.md)).

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

Pinned third-party TCB crates:

- `attested-mtls` 0.1.0 — engine-plane TLS material
- `ope-crypto` / `ope-envelope` / `ope-transport` / `ope-e2e` — git pin `d412005`
  (RB-05 `verify_and_open` + RB-06 transcript)
- `ope-protocol` — git pin `e82e9aa` (CPU endorsement wire type); Rust-only ARCH-CHAL
  work-kind constants are exposed by `ie-protocol`

Native `.so` hashes are pinned in [`config/tcb-pins.json`](config/tcb-pins.json).

## RB-05 / RB-06 (OPE auth)

| Env | Role |
|-----|------|
| `TEECHAT_OPE_ENGINE_TRUST_KEYS` | JSON `kid → Ed25519 public (base64url)`. Falls back to `TEECHAT_OPE_GATEWAY_TRUST_KEYS`. No `*` wildcard. |
| `TEECHAT_OPE_ENGINE_VERIFY` | `off` \| `signed-only` (default when keys set) \| `required` |
| `TEECHAT_OPE_ENGINE_EXPECTED_RECIPIENT` | Default `teechat-gateway` (chat clients) |
| `TEECHAT_OPE_RESPONSE_TRANSCRIPT` | **Keep off** until clients consume RB-06 frames |

`signed-only` authenticates signed chat envelopes via `verify_and_open` before hybrid decrypt; unsigned OpenAPI envelopes still use the legacy decrypt path.

### Packaging for the next train (flags stay off)

1. Tag `v*` → Actions packs `inference-engine-runtime-*.tar.gz` + `SHA256SUMS`.
2. TeaChat pins `ieRuntimeSha256` / asset in `config/engine-version.json` (+ platform-binaries row at cutover).
3. Guest install via TeaChat `install-engine-release.sh` / blue-green — **do not** set `TEECHAT_OPE_ENGINE_VERIFY` or `TEECHAT_OPE_RESPONSE_TRANSCRIPT` on prod until matching client builds are shipped.
4. IE-only ZD (same app-verity) is allowed for the binary bump; env flips for VERIFY/TRANSCRIPT are a **separate** change window.

## Build

Requires **Rust 1.88** (see `rust-toolchain.toml`).

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p ie-bin -- --check-tcb-pins
cargo run -p ie-bin -- --run
```

## Status

Capable of supervised pool boot, work-pull OPE inference, epoch rotation, attestation remint on scale/migrate, and SEC-029 gateway platform verify (env-gated).

**Release:** tag `vX.Y.Z` → Actions packs `inference-engine-runtime-*.tar.gz` + `SHA256SUMS` + `RELEASE_MANIFEST.json`. Production install and blue/green cutover are owned by the **TeeChat** ops tree (not this repo).

## License

Apache-2.0
