#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: ./kernel_decomp.sh <kernel-input> <kallsyms-file> [subset-file] [output-dir]

supported kernel-input types:
  - Android boot images
  - zImage kernel blobs
  - vmlinuz / compressed kernel images
  - raw kernel binaries
  - vmlinux ELF files

arguments:
  kernel-input    kernel container or kernel image to analyze
  kallsyms-file   kallsyms text file to drive symbol-focused decompilation
  subset-file     optional file listing only the symbols to decompile
  output-dir      optional output directory

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

if [[ $# -lt 2 || $# -gt 4 ]]; then
  usage >&2
  exit 1
fi

kernel_input="$1"
kallsyms_input="$2"
subset_file="${3:-}"
output_dir="${4:-}"

if [[ ! -f "$kernel_input" ]]; then
  echo "error: kernel input not found: $kernel_input" >&2
  exit 1
fi

if [[ ! -f "$kallsyms_input" ]]; then
  echo "error: kallsyms file not found: $kallsyms_input" >&2
  exit 1
fi

if [[ -n "$subset_file" && ! -f "$subset_file" ]]; then
  echo "error: subset file not found: $subset_file" >&2
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
kallsyms_base="$(basename "$kallsyms_input")"
kallsyms_stem="${kallsyms_base%.txt}"
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
kallsyms_report="${output_dir}/${kallsyms_stem}.report.txt"
kallsyms_overlay="${output_dir}/${kallsyms_stem}.extra-core.r2"
kallsyms_modules="${output_dir}/${kallsyms_stem}.modules.txt"
selected_symbols="${output_dir}/${kallsyms_stem}.selected-symbols.txt"
selected_skipped="${output_dir}/${kallsyms_stem}.skipped-symbols.txt"
r2_batch="${output_dir}/${kallsyms_stem}.decompile.r2"
r2_helper="${output_dir}/${input_prefix}.open-r2.sh"

if [[ -n "$subset_stem" ]]; then
  pseudo_c_output="${output_dir}/${kallsyms_stem}__${subset_stem}.pdc.c"
else
  pseudo_c_output="${output_dir}/${kallsyms_stem}.pdc.c"
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
  python -m pip install vmlinux-to-elf
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
    echo "kallsyms: $kallsyms_input"
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
    echo "kallsyms: $kallsyms_input"
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

python3 - "$vmlinux_elf" "$kallsyms_input" "$subset_file" "$kallsyms_report" "$kallsyms_overlay" "$kallsyms_modules" "$selected_symbols" "$selected_skipped" <<'PY'
import re
import subprocess
import sys
from pathlib import Path

elf_path = Path(sys.argv[1])
kallsyms_path = Path(sys.argv[2])
subset_path = Path(sys.argv[3]) if sys.argv[3] else None
report_path = Path(sys.argv[4])
overlay_path = Path(sys.argv[5])
modules_path = Path(sys.argv[6])
selected_path = Path(sys.argv[7])
skipped_path = Path(sys.argv[8])

sym_re = re.compile(r'^\s*\d+:\s+[0-9a-fA-F]+\s+\d+\s+\S+\s+\S+\s+\S+\s+\S+\s+(.+)$')
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
for line in readelf_symbols.splitlines():
    m = sym_re.match(line)
    if m:
        elf_symbols.add(m.group(1).strip())

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

module_lines = []
core_missing = []
selected = []
skipped = []
core_total = 0
code_total = 0

for line in kallsyms_path.read_text().splitlines():
    m = kallsyms_re.match(line)
    if not m:
        continue

    addr_s, sym_type, name, module = m.groups()
    addr = int(addr_s, 16)

    if module:
        module_lines.append(line)

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
        skipped.append((addr, sym_type, name, reason))
        continue

    selected.append((addr, sym_type, name, exec_section))

selected.sort()
skipped.sort()

with report_path.open("w") as fh:
    fh.write(f"input kallsyms: {kallsyms_path.name}\n")
    fh.write(f"kernel ELF: {elf_path.name}\n")
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
    if skipped:
        fh.write("\nSkipped symbols:\n")
        for addr, sym_type, name, reason in skipped[:500]:
            fh.write(f"0x{addr:x} {sym_type} {name} {reason}\n")
    if core_missing:
        fh.write("\nMissing core symbols:\n")
        for addr, sym_type, name, section in core_missing[:500]:
            fh.write(f"0x{addr:x} {sym_type} {name} {section}\n")

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
    for addr, sym_type, name, section in selected:
        fh.write(f"0x{addr:x}\t{sym_type}\t{name}\t{section}\n")

with skipped_path.open("w") as fh:
    for addr, sym_type, name, reason in skipped:
        fh.write(f"0x{addr:x}\t{sym_type}\t{name}\t{reason}\n")
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
  if [[ -n "$subset_file" ]]; then
    echo "?e // subset file: $(basename "$subset_file")"
  fi
  while IFS=$'\t' read -r addr sym_type name section; do
    [[ -n "$addr" ]] || continue
    echo "?e "
    echo "?e // ----- BEGIN ${name} (${sym_type}) [${section}] @ ${addr} -----"
    echo "s ${addr}"
    echo "af"
    echo "pdc"
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
echo "  $kallsyms_overlay"
echo "  $kallsyms_modules"
echo "  $selected_symbols"
echo "  $selected_skipped"
echo "  $pseudo_c_output"
echo "  $r2_batch"
echo "  $r2_helper"
