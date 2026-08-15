#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

python3 - \
  "$tmp/wrapped.bin" "$tmp/bare.bin" "$tmp/raw.bin" \
  "$tmp/truncated.bin" "$tmp/out-of-range.bin" <<'PY'
import struct
import sys
from pathlib import Path


def payload(base):
    vectors = [0x20001000, base + 0x51]
    for index in range(2, 18):
        if index == 15:
            vectors.append(base + 0x59)  # SysTick
        elif index == 16:
            vectors.append(base + 0x5d)  # IRQ0
        elif index == 17:
            vectors.append(base + 0x69)  # IRQ1; falls into known 0x6c
        else:
            vectors.append(base + 0x55)  # duplicated default handler
    blob = bytearray(struct.pack("<18I", *vectors))
    blob.extend(b"\x00" * (0x404 - len(blob)))
    for offset in (0x50, 0x54, 0x58, 0x5c):
        blob[offset:offset + 4] = b"\x70\x47\x00\xbf"  # bx lr; nop
    blob[0x60:0x64] = b"\x00\xbf\x00\xbf"  # fall through into callback
    blob[0x64:0x68] = b"\x70\x47\x00\xbf"
    blob[0x68:0x6c] = b"\x00\xbf\x00\xbf"  # vector into known function
    blob[0x6c:0x70] = b"\x70\x47\x00\xbf"
    # This aligned Thumb pointer is beyond the 256-entry vector scan, so its
    # target is deliberately generic/unnamed.
    struct.pack_into("<I", blob, 0x400, base + 0x65)
    return bytes(blob)

wrapped_header = bytearray(b"\xff" * 0x4000)
struct.pack_into("<I", wrapped_header, 0x100, 0x0800C047)
Path(sys.argv[1]).write_bytes(wrapped_header + payload(0x0800C000))
Path(sys.argv[2]).write_bytes(payload(0x08000000))
Path(sys.argv[3]).write_bytes(b"\x70\x47")
Path(sys.argv[4]).write_bytes(
    bytes(wrapped_header) + struct.pack("<II", 0x20001000, 0x0800C001)
)
Path(sys.argv[5]).write_bytes(wrapped_header + payload(0x08000000))
PY

"$repo/r2decomp" --decompiler pdc --analysis-mode aa \
  --function known_fallthrough@0x0800C060 \
  --function known_after_vector@0134266988 \
  --output-dir "$tmp/wrapped-out" "$tmp/wrapped.bin" >/dev/null

python3 - "$tmp/wrapped-out/wrapped.bin.functions.json" <<'PY'
import json
import sys
from pathlib import Path

functions = json.loads(Path(sys.argv[1]).read_text())
by_name = {fn["name"]: fn.get("addr", fn.get("offset")) for fn in functions}
expected = {
    "Reset_Handler": 0x0800C050,
    "Default_Handler": 0x0800C054,
    "SysTick_Handler": 0x0800C058,
    "IRQ0_Handler": 0x0800C05C,
    "known_fallthrough": 0x0800C060,
    "IRQ1_Handler": 0x0800C068,
    "known_after_vector": 0x0800C06C,
}
for name, address in expected.items():
    assert by_name[name] == address, (name, by_name)
addresses = {fn.get("addr", fn.get("offset")) for fn in functions}
assert 0x0800C064 in addresses, addresses
PY

grep -Fx 'afn Reset_Handler 0x800c050' "$tmp/wrapped-out/wrapped.bin.raw-seeds.r2"
grep -Fx 'afn Default_Handler 0x800c054' "$tmp/wrapped-out/wrapped.bin.raw-seeds.r2"
grep -Fx 'afn SysTick_Handler 0x800c058' "$tmp/wrapped-out/wrapped.bin.raw-seeds.r2"
grep -Fx 'afn IRQ0_Handler 0x800c05c' "$tmp/wrapped-out/wrapped.bin.raw-seeds.r2"
if grep -Fq '0x800c046' "$tmp/wrapped-out/wrapped.bin.raw-seeds.r2"; then
  echo "error: updater-header pointer was seeded" >&2
  exit 1
fi

# Headerless Cortex-M images must detect the vector at offset zero.
"$repo/r2decomp" --decompiler pdc --analysis-mode aa \
  --output-dir "$tmp/bare-out" "$tmp/bare.bin" >/dev/null
python3 - "$tmp/bare-out/bare.bin.functions.json" <<'PY'
import json
import sys
from pathlib import Path

functions = json.loads(Path(sys.argv[1]).read_text())
by_name = {fn["name"]: fn.get("addr", fn.get("offset")) for fn in functions}
assert by_name["Reset_Handler"] == 0x08000050, by_name
assert by_name["Default_Handler"] == 0x08000054, by_name
assert by_name["SysTick_Handler"] == 0x08000058, by_name
assert by_name["IRQ0_Handler"] == 0x0800005C, by_name
PY

# Explicit raw inputs without a vector must preserve a function at the load
# base and accept decimal addresses with leading zeroes.
"$repo/r2decomp" --raw --arch thumb --bits 16 --base 0134217728 \
  --function stub@0x08000000 --decompiler pdc --analysis-mode aa \
  --output-dir "$tmp/raw-out" "$tmp/raw.bin" >/dev/null
python3 - "$tmp/raw-out/raw.bin.functions.json" <<'PY'
import json
import sys
from pathlib import Path

functions = json.loads(Path(sys.argv[1]).read_text())
by_name = {fn["name"]: fn.get("addr", fn.get("offset")) for fn in functions}
assert by_name["stub"] == 0x08000000, by_name
PY
test ! -e "$tmp/raw-out/raw.bin.raw-seeds.r2"

# Truncated tables and reset handlers outside the inferred mapping are not
# valid auto-detect candidates.
for bad in "$tmp/truncated.bin" "$tmp/out-of-range.bin"; do
  if "$repo/r2decomp" --decompiler pdc --analysis-mode aa \
       --output-dir "$tmp/rejected" "$bad" >/dev/null 2>&1; then
    echo "error: invalid Cortex-M candidate was accepted: $bad" >&2
    exit 1
  fi
done

# An explicit non-Thumb override wins over vector-table auto-detection.
"$repo/r2decomp" --raw --arch aarch64 --bits 64 --base 0x08008000 \
  --decompiler pdc --analysis-mode aa \
  --output-dir "$tmp/arm64-out" "$tmp/wrapped.bin" >/dev/null
test ! -e "$tmp/arm64-out/wrapped.bin.raw-seeds.r2"

# Decimal parsing must not overflow Bash's signed arithmetic on 64-bit bases.
"$repo/r2decomp" --raw --arch aarch64 --bits 64 \
  --base 18446744073709551615 --decompiler pdc --analysis-mode aa \
  --output-dir "$tmp/u64-out" "$tmp/raw.bin" >"$tmp/u64.log"
grep -Fq 'base=18446744073709551615' "$tmp/u64.log"

# Raw whole-file string discovery can classify instruction bytes as strings
# and must never be used by the post-pass.
if grep -Fq '"izzj"' "$repo/r2decomp"; then
  echo "error: unsafe raw whole-file string inlining is enabled" >&2
  exit 1
fi
