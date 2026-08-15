#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

python3 - "$tmp/wrapped.bin" "$tmp/raw.bin" <<'PY'
import struct
import sys
from pathlib import Path

vectors = [0x20001000, 0x0800C041] + [0x0800C045] * 5 + [0] * 4 + [0x0800C045, 0x0800C045, 0, 0x0800C045, 0x0800C045]
payload = struct.pack("<16I", *vectors) + b"\x70\x47\x00\x00\x70\x47"
header = bytearray(b"\xff" * 0x4000)
struct.pack_into("<I", header, 0x100, 0x0800C049)
Path(sys.argv[1]).write_bytes(header + payload)
Path(sys.argv[2]).write_bytes(b"\x70\x47")
PY

"$repo/r2decomp" --decompiler pdc --analysis-mode aa \
  --output-dir "$tmp/wrapped-out" "$tmp/wrapped.bin" >/dev/null

python3 - "$tmp/wrapped-out/wrapped.bin.functions.json" <<'PY'
import json
import sys
from pathlib import Path

functions = json.loads(Path(sys.argv[1]).read_text())
by_name = {fn["name"]: fn.get("addr", fn.get("offset")) for fn in functions}
assert by_name["Reset_Handler"] == 0x0800C040, by_name
assert by_name["Default_Handler"] == 0x0800C044, by_name
PY

grep -Fx 'afn Reset_Handler 0x800c040' "$tmp/wrapped-out/wrapped.bin.raw-seeds.r2"
grep -Fx 'afn Default_Handler 0x800c044' "$tmp/wrapped-out/wrapped.bin.raw-seeds.r2"
if grep -Fq '0x800c048' "$tmp/wrapped-out/wrapped.bin.raw-seeds.r2"; then
  echo "error: updater-header pointer was seeded" >&2
  exit 1
fi

# Explicit raw inputs without a recognizable vector table must not receive an
# empty `-i` startup script.
"$repo/r2decomp" --raw --arch thumb --bits 16 --base 0x08000000 \
  --function stub@0x08000000 --decompiler pdc --analysis-mode aa \
  --output-dir "$tmp/raw-out" "$tmp/raw.bin" >/dev/null

# An explicit non-Thumb override wins over vector-table auto-detection.
"$repo/r2decomp" --raw --arch aarch64 --bits 64 --base 0x08008000 \
  --decompiler pdc --analysis-mode aa \
  --output-dir "$tmp/arm64-out" "$tmp/wrapped.bin" >/dev/null
test ! -e "$tmp/arm64-out/wrapped.bin.raw-seeds.r2"
