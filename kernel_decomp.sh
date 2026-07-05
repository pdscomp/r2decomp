#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: ./kernel_decomp.sh [--kallsyms-file FILE] [--subset-file FILE] [--output-dir DIR] [--kallsyms-remap auto|none|0xOFFSET] [--decompiler pdg|pdc] <kernel-input>

supported kernel-input types:
  - Android boot images
  - zImage kernel blobs
  - vmlinuz / compressed kernel images
  - raw kernel binaries
  - vmlinux ELF files

arguments:
  kernel-input    kernel container or kernel image to analyze

options:
  --kallsyms-file FILE
                  explicit external kallsyms file from a running system, such
                  as /proc/kallsyms; if omitted, generate and use an embedded
                  kallsyms-style file from the reconstructed ELF
  --subset-file FILE
                  optional file listing only the symbols to decompile; symbol
                  names are matched after kallsyms normalization
  --output-dir DIR
                  explicit output directory
  --kallsyms-remap MODE
                  keep default behavior with 'none', infer a single additive
                  remap with 'auto', or provide an explicit hex offset to
                  subtract from non-module kallsyms addresses
  --decompiler MODE
                  choose pseudo-C backend: 'pdg' (default, via r2ghidra) or
                  'pdc' (classic radare2 pseudo-C)

subset-file format:
  - one symbol name per line, or
  - full kallsyms lines; the symbol name is taken from column 3
  - blank lines and lines starting with '#' are ignored
EOF
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  usage
  exit 0
fi

remap_mode="auto"
decompiler="pdg"
kallsyms_input=""
subset_file=""
output_dir=""
positionals=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --kallsyms-file)
      if [[ $# -lt 2 ]]; then
        echo "error: --kallsyms-file requires a value" >&2
        exit 1
      fi
      kallsyms_input="$2"
      shift 2
      ;;
    --kallsyms-file=*)
      kallsyms_input="${1#*=}"
      shift
      ;;
    --subset-file)
      if [[ $# -lt 2 ]]; then
        echo "error: --subset-file requires a value" >&2
        exit 1
      fi
      subset_file="$2"
      shift 2
      ;;
    --subset-file=*)
      subset_file="${1#*=}"
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
    --kallsyms-remap)
      if [[ $# -lt 2 ]]; then
        echo "error: --kallsyms-remap requires a value" >&2
        exit 1
      fi
      remap_mode="$2"
      shift 2
      ;;
    --kallsyms-remap=*)
      remap_mode="${1#*=}"
      shift
      ;;
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

kernel_input="${positionals[0]}"

if [[ ! -f "$kernel_input" ]]; then
  echo "error: kernel input not found: $kernel_input" >&2
  exit 1
fi

if [[ -n "$kallsyms_input" && ! -f "$kallsyms_input" ]]; then
  echo "error: kallsyms file not found: $kallsyms_input" >&2
  exit 1
fi

if [[ -n "$subset_file" && ! -f "$subset_file" ]]; then
  echo "error: subset file not found: $subset_file" >&2
  exit 1
fi

case "$remap_mode" in
  none|auto)
    ;;
  0x*|0X*)
    ;;
  *)
    echo "error: unsupported --kallsyms-remap mode: $remap_mode" >&2
    exit 1
    ;;
esac

case "$decompiler" in
  pdg|pdc)
    ;;
  *)
    echo "error: unsupported --decompiler mode: $decompiler" >&2
    exit 1
    ;;
esac

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
need od
need dd
need cp
need binwalk
need python3
need gzip
need arm-none-eabi-readelf
need_r2

workspace_root="$(pwd)"
input_base="$(basename "$kernel_input")"
input_prefix="$input_base"
for suffix in ".vmlinux.elf" ".elf" ".img" ".bin"; do
  if [[ "$input_prefix" == *"$suffix" ]]; then
    input_prefix="${input_prefix%$suffix}"
    break
  fi
done
kallsyms_base="embedded-kallsyms.txt"
kallsyms_stem="embedded-kallsyms"
if [[ -n "$kallsyms_input" ]]; then
  kallsyms_base="$(basename "$kallsyms_input")"
  kallsyms_stem="${kallsyms_base%.txt}"
fi
subset_stem=""
if [[ -n "$subset_file" ]]; then
  subset_stem="$(basename "${subset_file%.*}")"
fi

safe_name() {
  printf '%s' "$1" | sed 's/[^A-Za-z0-9._-]/_/g'
}

if [[ -z "$output_dir" ]]; then
  output_dir="${workspace_root}/out/$(safe_name "${input_base}__${kallsyms_stem}")"
  if [[ -n "$subset_stem" ]]; then
    output_dir="${output_dir}__$(safe_name "$subset_stem")"
  fi
fi
mkdir -p "$output_dir"

source_info_txt="${output_dir}/${input_prefix}.source-info.txt"
payload_blob="${output_dir}/${input_prefix}.payload"
payload_binwalk_txt="${output_dir}/${input_prefix}.payload.binwalk.txt"
payload_comp="${output_dir}/${input_prefix}.payload.compressed-stream"
payload_raw="${output_dir}/${input_prefix}.payload.raw"
vmlinux_elf="${output_dir}/${input_prefix}.vmlinux.elf"
vmlinux_log="${output_dir}/${input_prefix}.vmlinux-to-elf.log"
embedded_kallsyms="${output_dir}/${input_prefix}.embedded-kallsyms.txt"
kallsyms_report="${output_dir}/${kallsyms_stem}.report.txt"
kallsyms_normalized="${output_dir}/${kallsyms_stem}.normalized.txt"
kallsyms_overlay="${output_dir}/${kallsyms_stem}.extra-core.r2"
kallsyms_modules="${output_dir}/${kallsyms_stem}.modules.txt"
selected_symbols="${output_dir}/${kallsyms_stem}.selected-symbols.txt"
selected_skipped="${output_dir}/${kallsyms_stem}.skipped-symbols.txt"
r2_batch="${output_dir}/${kallsyms_stem}.decompile-${decompiler}.r2"
r2_helper="${output_dir}/${input_prefix}.open-r2.sh"

if [[ -n "$subset_stem" ]]; then
  pseudo_c_output="${output_dir}/${kallsyms_stem}__${subset_stem}.${decompiler}.c"
else
  pseudo_c_output="${output_dir}/${kallsyms_stem}.${decompiler}.c"
fi

find_vmlinux_to_elf() {
  if command -v vmlinux-to-elf >/dev/null 2>&1; then
    command -v vmlinux-to-elf
    return
  fi

  if [[ -x .venv/bin/vmlinux-to-elf ]]; then
    echo ".venv/bin/vmlinux-to-elf"
    return
  fi

  python3 -m venv .venv
  . .venv/bin/activate
  python -m pip install --upgrade pip >/dev/null
  python -m pip install vmlinux-to-elf >/dev/null
  echo ".venv/bin/vmlinux-to-elf"
}

decompress_stream() {
  local desc="$1"
  local input="$2"
  local output="$3"

  case "$desc" in
    *gzip*)
      gzip -cd "$input" > "$output"
      ;;
    *XZ*|*xz*)
      need xz
      xz -cd "$input" > "$output"
      ;;
    *LZ4*|*lz4*)
      need lz4
      lz4 -d -c "$input" > "$output"
      ;;
    *LZO*|*lzo*)
      need lzop
      lzop -d -c "$input" > "$output"
      ;;
    *bzip2*)
      need bzip2
      bzip2 -cd "$input" > "$output"
      ;;
    *)
      echo "warning: unsupported compression description from binwalk: $desc" >&2
      return 1
      ;;
  esac
}

source_desc="$(file -b "$kernel_input")"
payload_input="$payload_blob"
payload_kind="generic"
kallsyms_source_mode="external"
effective_remap_mode="$remap_mode"

if [[ "$source_desc" == Android\ bootimg* ]]; then
  payload_kind="android-bootimg"
  set -- $(od -An -tu4 -j 8 -N 32 "$kernel_input")
  kernel_size="$1"
  kernel_addr="$2"
  ramdisk_size="$3"
  ramdisk_addr="$4"
  second_size="$5"
  second_addr="$6"
  tags_addr="$7"
  page_size="$8"

  {
    echo "kernel_input: $kernel_input"
    echo "input_kind: $payload_kind"
    echo "kallsyms: ${kallsyms_input:-<embedded-from-elf>}"
    echo "kallsyms_remap: $remap_mode"
    echo "decompiler: $decompiler"
    if [[ -n "$subset_file" ]]; then
      echo "subset_file: $subset_file"
    fi
    echo "output_dir: $output_dir"
    echo
    echo "kernel_size: $kernel_size"
    printf 'kernel_addr: 0x%x\n' "$kernel_addr"
    echo "ramdisk_size: $ramdisk_size"
    printf 'ramdisk_addr: 0x%x\n' "$ramdisk_addr"
    echo "second_size: $second_size"
    printf 'second_addr: 0x%x\n' "$second_addr"
    printf 'tags_addr: 0x%x\n' "$tags_addr"
    echo "page_size: $page_size"
    echo
    file "$kernel_input"
  } > "$source_info_txt"

  dd if="$kernel_input" of="$payload_blob" bs=1 skip="$page_size" count="$kernel_size" status=none
else
  if [[ "$source_desc" == ELF* ]]; then
    payload_kind="elf"
  elif [[ "$source_desc" == *"Linux kernel"*zImage* ]]; then
    payload_kind="zimage"
  elif [[ "$source_desc" == gzip* || "$source_desc" == XZ* || "$source_desc" == *"LZ4 compressed"* || "$source_desc" == *"LZO compressed"* || "$source_desc" == bzip2* ]]; then
    payload_kind="compressed-kernel"
  else
    payload_kind="kernel-image"
  fi

  {
    echo "kernel_input: $kernel_input"
    echo "input_kind: $payload_kind"
    echo "kallsyms: ${kallsyms_input:-<embedded-from-elf>}"
    echo "kallsyms_remap: $remap_mode"
    echo "decompiler: $decompiler"
    if [[ -n "$subset_file" ]]; then
      echo "subset_file: $subset_file"
    fi
    echo "output_dir: $output_dir"
    echo
    file "$kernel_input"
  } > "$source_info_txt"

  cp "$kernel_input" "$payload_blob"
fi

binwalk "$payload_input" > "$payload_binwalk_txt"

payload_desc="$(file -b "$payload_input")"
if [[ "$payload_desc" != ELF* ]]; then
  comp_line="$(awk '/gzip compressed data|XZ compressed data|LZ4 compressed data|LZO compressed data|bzip2 compressed data/ {off=$1; $1=""; sub(/^ +/, "", $0); print off "\t" $0; exit}' "$payload_binwalk_txt")"

  if [[ -n "$comp_line" ]]; then
    comp_offset="${comp_line%%$'\t'*}"
    comp_desc="${comp_line#*$'\t'}"
    dd if="$payload_input" of="$payload_comp" bs=1 skip="$comp_offset" status=none
    decompress_stream "$comp_desc" "$payload_comp" "$payload_raw" || true
  fi
fi

vmlinux_to_elf_bin="$(find_vmlinux_to_elf)"
"$vmlinux_to_elf_bin" "$payload_input" "$vmlinux_elf" 2>&1 | tee "$vmlinux_log"

if [[ -z "$kallsyms_input" ]]; then
  kallsyms_input="$embedded_kallsyms"
  kallsyms_base="$(basename "$kallsyms_input")"
  kallsyms_stem="${kallsyms_base%.txt}"
  kallsyms_report="${output_dir}/${kallsyms_stem}.report.txt"
  kallsyms_normalized="${output_dir}/${kallsyms_stem}.normalized.txt"
  kallsyms_overlay="${output_dir}/${kallsyms_stem}.extra-core.r2"
  kallsyms_modules="${output_dir}/${kallsyms_stem}.modules.txt"
  selected_symbols="${output_dir}/${kallsyms_stem}.selected-symbols.txt"
  selected_skipped="${output_dir}/${kallsyms_stem}.skipped-symbols.txt"
  r2_batch="${output_dir}/${kallsyms_stem}.decompile-${decompiler}.r2"
  if [[ -n "$subset_stem" ]]; then
    pseudo_c_output="${output_dir}/${kallsyms_stem}__${subset_stem}.${decompiler}.c"
  else
    pseudo_c_output="${output_dir}/${kallsyms_stem}.${decompiler}.c"
  fi
  kallsyms_source_mode="embedded"
  effective_remap_mode="none"

  python3 - "$vmlinux_elf" "$embedded_kallsyms" <<'PY'
import re
import subprocess
import sys
from pathlib import Path

elf_path = Path(sys.argv[1])
out_path = Path(sys.argv[2])
sym_re = re.compile(
    r'^\s*\d+:\s+([0-9a-fA-F]+)\s+\d+\s+(\S+)\s+(\S+)\s+\S+\s+(\S+)\s+(.+)$'
)

def map_char(sym_type: str, bind: str) -> str:
    if sym_type == "FUNC":
        if bind == "WEAK":
            return "W"
        if bind == "LOCAL":
            return "t"
        return "T"
    if sym_type == "OBJECT":
        if bind == "LOCAL":
            return "d"
        return "D"
    if bind == "LOCAL":
        return "n"
    return "N"

lines = []
seen = set()
readelf_symbols = subprocess.check_output(
    ["arm-none-eabi-readelf", "--wide", "-s", str(elf_path)],
    text=True,
)
for raw in readelf_symbols.splitlines():
    m = sym_re.match(raw)
    if not m:
        continue
    value_s, sym_type, bind, ndx, name = m.groups()
    name = name.strip()
    if not name or ndx in {"UND", "ABS"}:
        continue
    value = int(value_s, 16)
    if value == 0:
        continue
    if name in seen:
        continue
    seen.add(name)
    lines.append(f"{value:08x} {map_char(sym_type, bind)} {name}")

out_path.write_text("\n".join(lines) + ("\n" if lines else ""))
PY
fi

ensure_r2_decompiler "$vmlinux_elf"

python3 - "$vmlinux_elf" "$kallsyms_input" "$subset_file" "$kallsyms_report" "$kallsyms_normalized" "$kallsyms_overlay" "$kallsyms_modules" "$selected_symbols" "$selected_skipped" "$effective_remap_mode" "$kallsyms_source_mode" "$decompiler" <<'PY'
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

elf_path = Path(sys.argv[1])
kallsyms_path = Path(sys.argv[2])
subset_path = Path(sys.argv[3]) if sys.argv[3] else None
report_path = Path(sys.argv[4])
normalized_path = Path(sys.argv[5])
overlay_path = Path(sys.argv[6])
modules_path = Path(sys.argv[7])
selected_path = Path(sys.argv[8])
skipped_path = Path(sys.argv[9])
remap_mode = sys.argv[10]
kallsyms_source_mode = sys.argv[11]
decompiler = sys.argv[12]

sym_re = re.compile(r'^\s*\d+:\s+([0-9a-fA-F]+)\s+\d+\s+\S+\s+\S+\s+\S+\s+\S+\s+(.+)$')
section_re = re.compile(
    r'^\s*\[\s*(\d+)\]\s+(\S+)\s+\S+\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+\S+\s+(\S+)'
)
kallsyms_re = re.compile(r'^([0-9a-fA-F]+)\s+([A-Za-z])\s+(\S+)(?:\s+\[(.+)\])?$')

subset_names = None
if subset_path:
    subset_names = set()
    for raw in subset_path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = kallsyms_re.match(line)
        if m:
            subset_names.add(m.group(3))
        else:
            subset_names.add(line.split()[0])

readelf_sections = subprocess.check_output(
    ["arm-none-eabi-readelf", "--wide", "-S", str(elf_path)],
    text=True,
)
readelf_symbols = subprocess.check_output(
    ["arm-none-eabi-readelf", "--wide", "-s", str(elf_path)],
    text=True,
)

elf_symbols = set()
elf_symbol_values = {}
for line in readelf_symbols.splitlines():
    m = sym_re.match(line)
    if m:
        value = int(m.group(1), 16)
        name = m.group(2).strip()
        elf_symbols.add(name)
        elf_symbol_values.setdefault(name, set()).add(value)

alloc_ranges = []
exec_ranges = []
for line in readelf_sections.splitlines():
    m = section_re.match(line)
    if not m:
        continue
    _idx, name, addr_s, _off_s, size_s, flags = m.groups()
    addr = int(addr_s, 16)
    size = int(size_s, 16)
    if size == 0:
        continue
    if "A" in flags:
        alloc_ranges.append((addr, addr + size, name, flags))
    if "A" in flags and "X" in flags:
        exec_ranges.append((addr, addr + size, name, flags))

if not alloc_ranges:
    raise SystemExit("no allocatable sections found in reconstructed ELF")
if not exec_ranges:
    raise SystemExit("no executable allocatable sections found in reconstructed ELF")

def locate(addr, ranges):
    for start, end, name, flags in ranges:
        if start <= addr < end:
            return name
    return None

kallsyms_entries = []
for line in kallsyms_path.read_text().splitlines():
    m = kallsyms_re.match(line)
    if not m:
        continue
    addr_s, sym_type, name, module = m.groups()
    kallsyms_entries.append(
        {
            "line": line,
            "orig_addr": int(addr_s, 16),
            "sym_type": sym_type,
            "name": name,
            "module": module,
        }
    )

remap_offset = 0
remap_matches = []
remap_confidence = "not-requested"
remap_method = "none"

if remap_mode not in {"none", "auto"}:
    remap_offset = int(remap_mode, 16)
    remap_confidence = "explicit"
    remap_method = "explicit"
elif remap_mode == "auto":
    anchor_names = [
        "_stext",
        "stext",
        "_text",
        "start_kernel",
        "__start",
        "_start",
    ]
    for anchor in anchor_names:
        matching_entries = [
            entry for entry in kallsyms_entries
            if entry["module"] is None and entry["name"] == anchor
        ]
        values = elf_symbol_values.get(anchor)
        if len(matching_entries) == 1 and values and len(values) == 1:
            elf_value = next(iter(values))
            remap_offset = matching_entries[0]["orig_addr"] - elf_value
            remap_matches = [
                (anchor, matching_entries[0]["orig_addr"], elf_value)
            ]
            remap_confidence = f"anchor:{anchor}"
            remap_method = "anchor"
            break

    candidates = []
    if remap_method == "none":
        for entry in kallsyms_entries:
            if entry["module"] is not None:
                continue
            values = elf_symbol_values.get(entry["name"])
            if not values or len(values) != 1:
                continue
            elf_value = next(iter(values))
            candidates.append(
                (
                    entry["orig_addr"] - elf_value,
                    entry["name"],
                    entry["orig_addr"],
                    elf_value,
                )
            )
        if not candidates:
            raise SystemExit("auto remap requested but no shared unambiguous symbols were found between kallsyms and the ELF")
        counts = Counter(delta for delta, _name, _orig, _elf in candidates)
        remap_offset, remap_count = counts.most_common(1)[0]
        remap_matches = [
            (name, orig_addr, elf_value)
            for delta, name, orig_addr, elf_value in candidates
            if delta == remap_offset
        ]
        remap_ratio = remap_count / len(candidates)
        if remap_count >= 5 and remap_ratio >= 0.75:
            remap_confidence = f"{remap_count}/{len(candidates)} matches"
            remap_method = "majority"
        else:
            remap_offset = 0
            remap_matches = []
            remap_confidence = f"fallback-none:{remap_count}/{len(candidates)} matches"
            remap_method = "fallback-none"

normalized_lines = []

module_lines = []
core_missing = []
selected = []
skipped = []
core_total = 0
code_total = 0

for entry in kallsyms_entries:
    sym_type = entry["sym_type"]
    name = entry["name"]
    module = entry["module"]
    orig_addr = entry["orig_addr"]
    addr = orig_addr
    if module is None:
        addr = orig_addr - remap_offset

    normalized_lines.append(f"{addr:08x} {sym_type} {name}" + (f" [{module}]" if module else ""))

    if module:
        module_lines.append(entry["line"])

    alloc_section = locate(addr, alloc_ranges)
    exec_section = locate(addr, exec_ranges)

    if alloc_section is not None:
        core_total += 1
        if name not in elf_symbols:
            core_missing.append((addr, sym_type, name, alloc_section))

    if sym_type not in {"T", "t", "W", "w"}:
        continue

    code_total += 1

    if subset_names is not None and name not in subset_names:
        continue

    if exec_section is None:
        reason = "outside-exec-sections"
        if module:
            reason = f"module:{module}"
        elif alloc_section is not None:
            reason = f"nonexec-section:{alloc_section}"
        skipped.append((addr, orig_addr, sym_type, name, reason))
        continue

    selected.append((addr, orig_addr, sym_type, name, exec_section))

selected.sort()
skipped.sort()

with report_path.open("w") as fh:
    fh.write(f"input kallsyms: {kallsyms_path.name}\n")
    fh.write(f"kallsyms source mode: {kallsyms_source_mode}\n")
    fh.write(f"kernel ELF: {elf_path.name}\n")
    fh.write(f"decompiler: {decompiler}\n")
    fh.write(f"kallsyms remap mode: {remap_mode}\n")
    fh.write(f"kallsyms remap method: {remap_method}\n")
    fh.write(f"kallsyms remap offset: 0x{remap_offset:x}\n")
    fh.write(f"kallsyms remap confidence: {remap_confidence}\n")
    fh.write("alloc sections:\n")
    for start, end, name, flags in alloc_ranges:
        fh.write(f"  {name}: 0x{start:x}-0x{end:x} flags={flags}\n")
    fh.write("exec sections:\n")
    for start, end, name, flags in exec_ranges:
        fh.write(f"  {name}: 0x{start:x}-0x{end:x} flags={flags}\n")
    fh.write(f"core symbols in external kallsyms within ELF alloc ranges: {core_total}\n")
    fh.write(f"extra core symbols missing from ELF symtab: {len(core_missing)}\n")
    fh.write(f"module symbols present in external kallsyms: {len(module_lines)}\n")
    fh.write(f"code-like symbols in kallsyms file: {code_total}\n")
    fh.write(f"selected symbols for pseudo-C export: {len(selected)}\n")
    fh.write(f"skipped requested symbols: {len(skipped)}\n")
    if subset_names is not None:
        fh.write(f"subset entries requested: {len(subset_names)}\n")
    if remap_matches:
        fh.write("remap match samples:\n")
        for name, orig_addr, elf_value in remap_matches[:20]:
            fh.write(f"  {name}: runtime=0x{orig_addr:x} file=0x{elf_value:x}\n")
    if skipped:
        fh.write("\nSkipped symbols:\n")
        for addr, orig_addr, sym_type, name, reason in skipped[:500]:
            fh.write(f"runtime=0x{orig_addr:x} file=0x{addr:x} {sym_type} {name} {reason}\n")
    if core_missing:
        fh.write("\nMissing core symbols:\n")
        for addr, sym_type, name, section in core_missing[:500]:
            fh.write(f"0x{addr:x} {sym_type} {name} {section}\n")

normalized_path.write_text("\n".join(normalized_lines) + ("\n" if normalized_lines else ""))

with overlay_path.open("w") as fh:
    if not core_missing:
        fh.write("# no extra core-kernel symbols were missing from the reconstructed ELF\n")
    else:
        used = set()
        for addr, _sym_type, name, _section in core_missing:
            clean = re.sub(r"[^A-Za-z0-9_.$]", "_", name)
            if not clean:
                clean = "unnamed"
            if clean in used:
                clean = f"{clean}_{addr:x}"
            used.add(clean)
            fh.write(f"f ext.{clean} @ 0x{addr:x}\n")

modules_path.write_text("\n".join(module_lines) + ("\n" if module_lines else ""))

with selected_path.open("w") as fh:
    for addr, orig_addr, sym_type, name, section in selected:
        fh.write(f"0x{addr:x}\t0x{orig_addr:x}\t{sym_type}\t{name}\t{section}\n")

with skipped_path.open("w") as fh:
    for addr, orig_addr, sym_type, name, reason in skipped:
        fh.write(f"0x{addr:x}\t0x{orig_addr:x}\t{sym_type}\t{name}\t{reason}\n")
PY

selected_count="$(wc -l < "$selected_symbols" | tr -d ' ')"
if [[ "$selected_count" -eq 0 ]]; then
  echo "error: no code symbols from $kallsyms_input were selectable for decompilation" >&2
  echo "see: $kallsyms_report" >&2
  exit 1
fi

{
  echo "e scr.color=0"
  echo "e scr.interactive=false"
  echo "e bin.cache=true"
  echo "aa"
  echo "?e // pseudo-c export driven by ${kallsyms_base}"
  echo "?e // decompiler: ${decompiler}"
  echo "?e // kallsyms remap mode: ${effective_remap_mode}"
  echo "?e // kallsyms source mode: ${kallsyms_source_mode}"
  if [[ -n "$subset_file" ]]; then
    echo "?e // subset file: $(basename "$subset_file")"
  fi
  while IFS=$'\t' read -r addr orig_addr sym_type name section; do
    [[ -n "$addr" ]] || continue
    echo "?e "
    echo "?e // ----- BEGIN ${name} (${sym_type}) [${section}] file=${addr} runtime=${orig_addr} -----"
    echo "s ${addr}"
    echo "af"
    echo "${decompiler}"
    echo "?e // ----- END ${name} -----"
  done < "$selected_symbols"
  echo "q"
} > "$r2_batch"

r2 -q -e bin.cache=true -e scr.color=0 -i "$r2_batch" "$vmlinux_elf" > "$pseudo_c_output"

cat > "$r2_helper" <<EOF
#!/usr/bin/env bash
set -euo pipefail
cd "$workspace_root"
if [[ -s "$kallsyms_overlay" ]]; then
  exec r2 -e bin.cache=true -i "$kallsyms_overlay" "\$@" "$vmlinux_elf"
else
  exec r2 -e bin.cache=true "\$@" "$vmlinux_elf"
fi
EOF
chmod +x "$r2_helper"

echo "wrote:"
echo "  $output_dir"
echo "  $source_info_txt"
echo "  $payload_blob"
echo "  $payload_binwalk_txt"
if [[ -f "$payload_raw" ]]; then
  echo "  $payload_comp"
  echo "  $payload_raw"
fi
echo "  $vmlinux_elf"
echo "  $vmlinux_log"
echo "  $kallsyms_report"
echo "  $kallsyms_normalized"
echo "  $kallsyms_overlay"
echo "  $kallsyms_modules"
echo "  $selected_symbols"
echo "  $selected_skipped"
echo "  $pseudo_c_output"
echo "  $r2_batch"
echo "  $r2_helper"
