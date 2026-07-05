#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: ./decomp.sh [--decompiler pdg|pdc] [--analysis-mode aa|aaa] [--output-dir DIR] <elf-binary>

Generates a single combined pseudo-C export for every discovered function in
the ELF and writes it under the current working directory by default.
EOF
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  usage
  exit 0
fi

decompiler="pdg"
analysis_mode="aa"
output_dir=""
positionals=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --decompiler)
      if [[ $# -lt 2 ]]; then
        echo "error: --decompiler requires a value" >&2
        exit 1
      fi
      decompiler="$2"
      shift 2
      ;;
    --decompiler=*)
      decompiler="${1#*=}"
      shift
      ;;
    --analysis-mode)
      if [[ $# -lt 2 ]]; then
        echo "error: --analysis-mode requires a value" >&2
        exit 1
      fi
      analysis_mode="$2"
      shift 2
      ;;
    --analysis-mode=*)
      analysis_mode="${1#*=}"
      shift
      ;;
    --output-dir)
      if [[ $# -lt 2 ]]; then
        echo "error: --output-dir requires a value" >&2
        exit 1
      fi
      output_dir="$2"
      shift 2
      ;;
    --output-dir=*)
      output_dir="${1#*=}"
      shift
      ;;
    --)
      shift
      while [[ $# -gt 0 ]]; do
        positionals+=("$1")
        shift
      done
      ;;
    -*)
      echo "error: unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
    *)
      positionals+=("$1")
      shift
      ;;
  esac
done

if [[ ${#positionals[@]} -ne 1 ]]; then
  usage >&2
  exit 1
fi

case "$decompiler" in
  pdg|pdc)
    ;;
  *)
    echo "error: unsupported --decompiler mode: $decompiler" >&2
    exit 1
    ;;
esac

case "$analysis_mode" in
  aa|aaa)
    ;;
  *)
    echo "error: unsupported --analysis-mode: $analysis_mode" >&2
    exit 1
    ;;
esac

elf_input="${positionals[0]}"
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

need_r2pm() {
  command -v r2pm >/dev/null 2>&1 || {
    cat >&2 <<'EOF'
error: r2pm is required to install the r2ghidra plugin for pdg output

install radare2 with:
  git clone https://github.com/radareorg/radare2
  cd radare2 ; sys/install.sh
EOF
    exit 1
  }
}

r2pm_pdg_prereqs() {
  local missing=()
  local tool
  for tool in git make gcc g++ pkg-config patch unzip wget; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      missing+=("$tool")
    fi
  done

  if [[ ${#missing[@]} -gt 0 ]]; then
    echo "error: pdg needs build tools for the r2ghidra install path: ${missing[*]}" >&2
    echo "install them first, then rerun with pdg or use --decompiler pdc" >&2
    exit 1
  fi
}

r2_has_pdg() {
  local target="$1"
  local probe=""
  probe="$(r2 -q -e scr.color=0 -e scr.interactive=false -c 'pdg?; q' "$target" 2>&1 || true)"
  [[ "$probe" == *"Native Ghidra decompiler plugin"* ]] && [[ "$probe" != *"install the plugin"* ]]
}

ensure_r2_decompiler() {
  local target="$1"

  if [[ "$decompiler" == "pdc" ]]; then
    return
  fi

  need_r2pm
  r2pm_pdg_prereqs
  if r2_has_pdg "$target"; then
    return
  fi

  echo "info: installing r2ghidra with r2pm -ci r2ghidra" >&2
  if ! r2pm -ci r2ghidra; then
    echo "info: initializing r2pm package database and retrying r2ghidra install" >&2
    r2pm -U
    r2pm -ci r2ghidra
  fi

  if ! r2_has_pdg "$target"; then
    echo "error: requested pdg output, but r2ghidra is still unavailable after installation" >&2
    exit 1
  fi
}

need file
need python3
need_r2
ensure_r2_decompiler "$elf_input"

file_desc="$(file -b "$elf_input")"
if [[ "$file_desc" != ELF* ]]; then
  echo "error: input is not an ELF binary: $elf_input" >&2
  echo "file says: $file_desc" >&2
  exit 1
fi

elf_base="$(basename "$elf_input")"
if [[ -z "$output_dir" ]]; then
  output_dir="$(pwd)"
fi
mkdir -p "$output_dir"
if [[ ! -w "$output_dir" ]]; then
  echo "error: output directory is not writable: $output_dir" >&2
  exit 1
fi

funcs_json="${output_dir}/${elf_base}.functions.json"
if [[ "$decompiler" == "pdg" ]]; then
  r2_batch="${output_dir}/${elf_base}.decompile-all-pdg.r2"
  pseudo_c_output="${output_dir}/${elf_base}.pdg.c"
else
  r2_batch="${output_dir}/${elf_base}.decompile-all-pdc.r2"
  pseudo_c_output="${output_dir}/${elf_base}.pdc.c"
fi
r2 -q -e bin.cache=true -c "${analysis_mode}; aflj; q" "$elf_input" > "$funcs_json"

python3 - "$funcs_json" "$r2_batch" "$decompiler" "$analysis_mode" <<'PY'
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
    fh.write(f"{sys.argv[4]}\n")
    fh.write(f"?e // pseudo-c export for all discovered functions via {sys.argv[3]}\n")
    fh.write(f"?e // analysis mode: {sys.argv[4]}\n")
    for fn in data:
        offset = fn.get("offset")
        name = fn.get("name", "sub")
        size = fn.get("size", 0)
        if offset is None:
            continue
        fh.write("?e \n")
        fh.write(f"?e // ----- BEGIN {name} size={size} @ 0x{offset:x} -----\n")
        fh.write(f"s 0x{offset:x}\n")
        fh.write(f"{sys.argv[3]}\n")
        fh.write(f"?e // ----- END {name} -----\n")
    fh.write("q\n")
PY

r2 -q -e bin.cache=true -e scr.color=0 -i "$r2_batch" "$elf_input" > "$pseudo_c_output"

echo "wrote:"
echo "  $funcs_json"
echo "  $r2_batch"
echo "  $pseudo_c_output"
