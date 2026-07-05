#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: ./decomp.sh <elf-binary>

Generates a single combined pseudo-C export for every discovered function in
the ELF and writes it next to the input file.
EOF
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -ne 1 ]]; then
  usage >&2
  exit 1
fi

elf_input="$1"
if [[ ! -f "$elf_input" ]]; then
  echo "error: ELF input not found: $elf_input" >&2
  exit 1
fi

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "error: missing required tool: $1" >&2
    exit 1
  }
}

need_r2() {
  if command -v r2 >/dev/null 2>&1; then
    return
  fi

  cat >&2 <<'EOF'
error: radare2 (r2) is not installed

install it with:
  git clone https://github.com/radareorg/radare2
  cd radare2 ; sys/install.sh
EOF
  exit 1
}

need file
need python3
need_r2

file_desc="$(file -b "$elf_input")"
if [[ "$file_desc" != ELF* ]]; then
  echo "error: input is not an ELF binary: $elf_input" >&2
  echo "file says: $file_desc" >&2
  exit 1
fi

elf_dir="$(cd "$(dirname "$elf_input")" && pwd)"
elf_base="$(basename "$elf_input")"
funcs_json="${elf_input}.functions.json"
r2_batch="${elf_input}.decompile-all.r2"
pseudo_c_output="${elf_input}.pdc.c"

r2 -q -e bin.cache=true -c 'aa; aflj; q' "$elf_input" > "$funcs_json"

python3 - "$funcs_json" "$r2_batch" <<'PY'
import json
import sys
from pathlib import Path

funcs_path = Path(sys.argv[1])
batch_path = Path(sys.argv[2])

data = json.loads(funcs_path.read_text() or "[]")

with batch_path.open("w") as fh:
    fh.write("e scr.color=0\n")
    fh.write("e scr.interactive=false\n")
    fh.write("e bin.cache=true\n")
    fh.write("aa\n")
    fh.write("?e // pseudo-c export for all discovered functions\n")
    for fn in data:
        offset = fn.get("offset")
        name = fn.get("name", "sub")
        size = fn.get("size", 0)
        if offset is None:
            continue
        fh.write("?e \n")
        fh.write(f"?e // ----- BEGIN {name} size={size} @ 0x{offset:x} -----\n")
        fh.write(f"s 0x{offset:x}\n")
        fh.write("pdc\n")
        fh.write(f"?e // ----- END {name} -----\n")
    fh.write("q\n")
PY

r2 -q -e bin.cache=true -e scr.color=0 -i "$r2_batch" "$elf_input" > "$pseudo_c_output"

echo "wrote:"
echo "  $funcs_json"
echo "  $r2_batch"
echo "  $pseudo_c_output"
