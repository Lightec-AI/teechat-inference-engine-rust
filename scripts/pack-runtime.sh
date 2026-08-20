#!/usr/bin/env bash
# Pack measured Rust IE runtime tarball + SHA256SUMS + RELEASE_MANIFEST.json
# (port of vendor/inference-engine/scripts/pack-runtime.mjs semantics).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${TEECHAT_IE_PACK_OUT:-$ROOT/dist/release}"
VERSION="${TEECHAT_ENGINE_BUILD_VERSION:-$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["packages"][0]["version"])')}"
VERSION="${VERSION#v}"
TAR_NAME="inference-engine-runtime-${VERSION}.tar.gz"

mkdir -p "$OUT_DIR"
echo ">> building release binary"
cargo build --release --locked --frozen -p ie-bin

BIN="$ROOT/target/release/teechat-inference-engine"
if [[ ! -x "$BIN" ]]; then
  echo "!! missing $BIN" >&2
  exit 1
fi

STAGE="$OUT_DIR/stage"
rm -rf "$STAGE"
mkdir -p "$STAGE/bin" "$STAGE/config"
cp "$BIN" "$STAGE/bin/teechat-inference-engine"
cp "$ROOT/config/tcb-pins.json" "$STAGE/config/tcb-pins.json"
cat >"$STAGE/README.txt" <<EOF
TeeChat InferenceEngine (Rust) runtime bundle.
Primary measured artifact: ${TAR_NAME}
Engine binary_sha256 is independent of libope_ffi.so and libattested_mtls.so (see tcb-pins.json).
EOF

TAR_PATH="$OUT_DIR/$TAR_NAME"
tar -czf "$TAR_PATH" -C "$STAGE" .

sha256() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    sha256sum "$1" | awk '{print $1}'
  fi
}

IE_RUNTIME_SHA256="$(sha256 "$TAR_PATH")"
IE_BINARY_SHA256="$(sha256 "$BIN")"
OPE_FFI_SHA256="$(python3 -c 'import json; print(json.load(open("'"$ROOT/config/tcb-pins.json"'"))["ope"]["libopeFfiSha256"].lower())')"
AMT_SHA256="$(python3 -c 'import json; print(json.load(open("'"$ROOT/config/tcb-pins.json"'"))["attestedMtls"]["libAttestedMtlsSha256"].lower())')"

# Clients fingerprint the attested ELF (bin/teechat-inference-engine), not only the tarball.
# Keep BOTH digests in SHA256SUMS so allowlist / GitHub-release scanners can match either.
cat >"$OUT_DIR/SHA256SUMS" <<EOF
${IE_RUNTIME_SHA256}  ${TAR_NAME}
${IE_BINARY_SHA256}  bin/teechat-inference-engine
EOF

python3 - <<PY
import json, pathlib
out = pathlib.Path("$OUT_DIR")
manifest = {
  "schema": "teechat-inference-engine-release/v2",
  "version": "$VERSION",
  "tag": f"v$VERSION",
  "ieRuntimeSha256": "$IE_RUNTIME_SHA256",
  "ieRuntimeAsset": "$TAR_NAME",
  "ieBinarySha256": "$IE_BINARY_SHA256",
  "ieBinaryAsset": "bin/teechat-inference-engine",
  "opeFfiSha256": "$OPE_FFI_SHA256",
  "attestedMtlsSha256": "$AMT_SHA256",
  "notes": "Primary measured artifacts: inference-engine-runtime-*.tar.gz (ieRuntimeSha256) and "
           "bin/teechat-inference-engine ELF (ieBinarySha256; client attestation fingerprint). "
           "OPE FFI and attested-mtls are independent TCBs from config/tcb-pins.json.",
}
(out / "RELEASE_MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
PY

echo ">> pack-runtime: ${TAR_NAME} sha256=${IE_RUNTIME_SHA256:0:16}… elf=${IE_BINARY_SHA256:0:16}…"
echo ">> wrote ${OUT_DIR}/SHA256SUMS + RELEASE_MANIFEST.json"

# RB-22: bound SBOM of measured binary (component hash = ie-bin sha256).
SBOM_PATH="$OUT_DIR/inference-engine-runtime-${VERSION}.sbom.json"
python3 - "$SBOM_PATH" "$IE_BINARY_SHA256" "$VERSION" <<'PY'
import json, sys
path, sha, ver = sys.argv[1], sys.argv[2], sys.argv[3]
doc = {
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {"component": {"type": "application", "name": "teechat-inference-engine", "version": ver}},
  "components": [{
    "type": "application",
    "name": "teechat-inference-engine",
    "version": ver,
    "hashes": [{"alg": "SHA-256", "content": sha}],
  }],
}
open(path, "w", encoding="utf8").write(json.dumps(doc, indent=2) + "\n")
print("OK: wrote", path)
PY
echo "SBOM=$SBOM_PATH"
