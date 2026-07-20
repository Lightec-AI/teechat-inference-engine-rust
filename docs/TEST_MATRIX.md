# Test matrix: TypeScript `test/*.test.ts` → Rust

Gate: `cargo test --workspace` + `cargo clippy --workspace --all-targets -- -D warnings`.

| TypeScript test | Rust location | Notes |
|-----------------|---------------|-------|
| `measurements.test.ts` | `ie-attestation/src/measurements.rs` | Engine ≠ OPE FFI ≠ attested-mtls |
| `engine-epoch.test.ts` | `ie-engine/src/epoch/engine_epoch.rs` | Epoch create + signing |
| `epoch-rotator.test.ts` | `ie-engine/src/epoch/rotator.rs` | Initial ephemeral register |
| `epoch-rotation-policy.test.ts` | `ie-engine/src/epoch/policy.rs` | Policy defaults |
| `rotating-decryptor.test.ts` | `ie-engine/src/epoch/rotating_decryptor.rs` | Overlap + prune |
| `pool-cutover.test.ts` | `ie-engine/src/cutover.rs` | Drain/scale planning |
| `pool-drain-control.test.ts` | `ie-engine/src/controls/drain.rs` | JSON parse |
| `pool-scale-control.test.ts` | `ie-engine/src/controls/scale.rs` | JSON parse |
| `pool-status-control.test.ts` | `ie-engine/src/controls/status.rs` | Snapshot schema |
| `gateway-migration.test.ts` | `ie-engine/src/gateway_migration.rs` | Migration plan |
| `gateway-migration-control.test.ts` | `ie-engine/src/controls/migrate.rs` | JSON parse |
| `supervised-pool-cutover.test.ts` | `ie-engine/src/pool.rs` | Drain + scale integration |
| `supervised-pool-migrate.test.ts` | `ie-engine/src/pool.rs` | Gateway URL migration |
| `supervised-pool-reconnect.test.ts` | `ie-engine/src/pool.rs` | Circuit / reconnect skeleton |
| `attestation-fixture-backend.test.ts` | `ie-attestation/src/fixture.rs` | Fixture + mock HMAC |
| `attestation-policy-file.test.ts` | `ie-attestation/src/policy.rs` | Policy allowlists |
| `gpu-attestation.test.ts` | `ie-attestation/src/nv_cc/verify.rs` | NV claim validation |
| `metering.test.ts` | `ie-engine/src/ops/metering.rs` | Usage report signing |
| `prefill.test.ts` | `ie-engine/src/ops/prefill.rs` | KV prefill planner |
| `instance-id.test.ts` | `ie-engine/src/ops/instance_id.rs` | Slot / instance id |
| `ope-inference*.test.ts` | `ie-engine/src/infer` + `tests/pull_infer_roundtrip.rs` | Gate + decrypt/encrypt + mock H2 IT |
| `pool-client-session-errors.test.ts` | `ie-engine/src/plane` | Transport + pull worker errors |
| `native-ope-ffi*.test.ts` | — | **Excluded** — Rust uses `ope-e2e` in-process, not koffi FFI |
| `vllm-chat*.test.ts` | `ie-upstream/src/client.rs` | Partial SSE/routing coverage |
| `browser-trust.test.ts` | — | **Excluded** — browser/WASM client scope |

## Measurement invariants (must not regress)

1. `engine.binary_sha256` — IE runtime bundle (`TEECHAT_IE_RUNTIME_SHA256` / `RELEASE_MANIFEST.json`)
2. `ope.libope_ffi_sha256` — independent OPE TCB from `config/tcb-pins.json`
3. `attested_mtls.lib_attested_mtls_sha256` — independent attested-mtls TCB

Test: `ie-attestation::measurements::engine_sha_distinct_from_ope_ffi_and_attested_mtls`
