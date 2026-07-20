# Staging canary: `engine-rust-canary`

**Do not install on production hosts until the acceptance checklist below is green.**

The Rust InferenceEngine canary uses a reserved engine id so it never collides with production `engine-prod-*` slots:

```bash
export TEECHAT_OPE_ENGINE_ID=engine-rust-canary
```

## Measured release order (GitHub + platform manifest)

Clients verify `engine.binary_sha256` against **both** this repo’s GitHub Release
`SHA256SUMS` and TeeChat `platform-binaries.json` (row `releaseUrl` must point here).
See TeaChat [client-attestation-github-trust.md](https://github.com/Lightec-AI/TeaChat/blob/main/docs/ops/client-attestation-github-trust.md).

**No client code change** is required for Rust IE — set the manifest row’s `releaseUrl`
to this repo; `engine-trust-client` already follows it.

| Step | Action | Notes |
|------|--------|-------|
| 1 | Bump workspace version in `Cargo.toml`; local smoke (`cargo test` / `clippy` / `pack-runtime.sh`) | Laptop digest is **not** the measured pin |
| 2 | Commit, tag `vX.Y.Z`, push | Actions (`.github/workflows/release.yml`) builds **linux-amd64** |
| 3 | **Watch** Release workflow; wait for assets | `gh run watch -R Lightec-AI/teechat-inference-engine-rust` |
| 4 | **In TeaChat**, unshift `engine.active[]` + append `allowedEngineBinarySha256` from CI digests | `curl …/SHA256SUMS` + `RELEASE_MANIFEST.json`; copy vLLM/OPE from live row; bump `publishedAt`; validate |
| 5 | Sync platform manifest when ops env allows | `pnpm ops:sync-prod-platform-manifest -- --no-restart` if version-only |
| 6 | Install **GitHub** tarball on staging guest | Pin `TEECHAT_IE_RUNTIME_SHA256` to the CI digest; start as `engine-rust-canary` |

Step 4 is part of the cut, not a separate handoff: after a successful Release, write the
pins in the same session (see TeaChat `docs/ops/client-attestation-github-trust.md`).

```bash
curl -fsSL "https://github.com/Lightec-AI/teechat-inference-engine-rust/releases/download/v${VER}/SHA256SUMS"
# must equal platform-binaries.json engine row binarySha256
# and attestation-policy.prod.json allowedEngineBinarySha256
```

## Local smoke (before tag; no prod/manifest pin)

1. Build and pack the runtime:

   ```bash
   cargo test --workspace
   cargo clippy --workspace --all-targets -- -D warnings
   bash scripts/pack-runtime.sh
   ```

2. On a **staging** engine guest only, you may install a local tarball from `dist/release/`
   for bring-up debugging — but **client trust** will fail until the guest runs the
   **same** bytes published on the GitHub Release and listed in the manifest.

3. Load staging env (`.env.staging` or equivalent):

   ```bash
   export TEECHAT_ENV=staging
   export TEECHAT_OPE_ENGINE_ID=engine-rust-canary
   export TEECHAT_ENGINE_GATEWAY_URL=https://<staging-gateway>:8788
   export TEECHAT_VLLM_BASE_URL=http://127.0.0.1:11434/v1
   ```

4. Start the engine:

   ```bash
   ./bin/teechat-inference-engine --run --cwd /opt/teechat/inference-engine
   ```

## Acceptance checklist

| Step | Action | Pass criteria |
|------|--------|---------------|
| 1 | Register | Engine attested connect succeeds; pool boots to configured target (or staging half-pool fraction) |
| 2 | Ephemeral | Initial epoch registers on all live sessions (`201` on engine-plane ephemeral path) |
| 3 | Pull | Work-pull worker accepts at least one idle session |
| 4 | Confidential round-trip | One OPE inference request decrypts, upstream completes, encrypted response returns |
| 5 | Drain control | Write `/etc/teechat/engine-pool-drain-<slot>.json` + `SIGUSR2`; idle sessions drain without restart |
| 6 | Scale control | Write `/etc/teechat/engine-pool-scale-<slot>.json`; pool grows in-process |
| 7 | Status | `/etc/teechat/engine-pool-status-<slot>.json` publishes `teechat-engine-pool-status/v1` with `live_sessions` |
| 8 | Client trust | Prod-policy client: GitHub `source: "github"` for engine hash (or CN `manifest_fallback`); no `engine_hash_not_on_release` |

## Explicit non-goals until green

- No replace of `engine-prod-1` or production blue/green cutover
- No TeeChat `minor-release` packaging of Rust IE as the default prod engine
- No fail-closed client changes requiring Rust-only attestation claims

When all rows pass on staging, document the CI `ieRuntimeSha256` in the release notes — still **do not** promote to prod without an explicit ops runbook sign-off.
