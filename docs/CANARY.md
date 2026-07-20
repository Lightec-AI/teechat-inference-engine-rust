# Staging canary: `engine-rust-canary`

**Do not install on production hosts until the acceptance checklist below is green.**

The Rust InferenceEngine canary uses a reserved engine id so it never collides with production `engine-prod-*` slots:

```bash
export TEECHAT_OPE_ENGINE_ID=engine-rust-canary
```

## Staging smoke (no prod install)

1. Build and pack the runtime:

   ```bash
   cargo test --workspace
   cargo clippy --workspace --all-targets -- -D warnings
   bash scripts/pack-runtime.sh
   ```

2. On a **staging** engine guest only, install the tarball from `dist/release/` (not prod blue/green slots).

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
| 3 | Pull | Work-pull worker accepts at least one idle session (M2 parity when landed) |
| 4 | Confidential round-trip | One OPE inference request decrypts, upstream completes, encrypted response returns |
| 5 | Drain control | Write `/etc/teechat/engine-pool-drain-<slot>.json` + `SIGUSR2`; idle sessions drain without restart |
| 6 | Scale control | Write `/etc/teechat/engine-pool-scale-<slot>.json`; pool grows in-process |
| 7 | Status | `/etc/teechat/engine-pool-status-<slot>.json` publishes `teechat-engine-pool-status/v1` with `live_sessions` |

## Explicit non-goals until green

- No replace of `engine-prod-1` or production blue/green cutover
- No TeeChat `minor-release` packaging of Rust IE
- No fail-closed client changes requiring Rust-only attestation claims

When all rows pass on staging, document the manifest SHA256 in the release notes — still **do not** promote to prod without an explicit ops runbook sign-off.
