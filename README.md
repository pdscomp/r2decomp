# r2decomp

Mission: make radare2 pseudo-C generation fast and practical for ELF binaries, with a kernel pipeline that can reconstruct Linux and Android kernel images into ELF and selectively decompile symbols for analysis.

We default to the `r2ghidra` plugin for higher-quality `pdg` pseudo-C output, and keep classic built-in radare2 `pdc` mode available when you want the original output or a fallback path.

Command-line pseudo-C decompilation for:

- Linux kernel images, including Android boot images, `zImage`, `vmlinuz`, raw kernel blobs, and `vmlinux` ELF files
- Ordinary ELF binaries such as `.ko` modules

The scripts use `radare2` for analysis, `r2ghidra` for higher-quality `pdg` pseudo-C by default, and `vmlinux-to-elf` to rebuild a usable kernel ELF when the input is not already ELF.

## Install

The scripts expect a few host tools to be present:

- `radare2` and `r2pm`
- `binwalk`
- `python3`
- `python3-venv` and `python3-pip` for the kernel script's local virtualenv bootstrap
- `file`, `od`, `dd`, `cp`, `gzip`
- `arm-none-eabi-readelf`

For the default `pdg` backend, `r2ghidra` is installed automatically through `r2pm`, but that path needs build tools available on the host:

- `git`
- `make`
- `gcc`
- `g++`
- `pkg-config`
- `patch`
- `unzip`
- `wget`

On Debian/Ubuntu-style systems, a practical baseline is:

```bash
sudo apt install radare2 binwalk python3 python3-venv python3-pip file coreutils gzip binutils gcc g++ make pkg-config patch unzip wget
```

If `r2` is missing, the scripts print:

```bash
git clone https://github.com/radareorg/radare2
cd radare2 ; sys/install.sh
```

## Scripts

- `r2decomp-kernel`: extract or normalize a kernel image, rebuild `vmlinux.elf`, prepare symbols, and export pseudo-C
- `r2decomp`: take an ELF or supported raw firmware image and export pseudo-C
  for the whole binary

## Requirements

`r2decomp-kernel` needs:

- `r2`
- `binwalk`
- `python3`
- `file`
- `od`
- `dd`
- `cp`
- `gzip`
- `arm-none-eabi-readelf`

If `pdg` is selected and `r2ghidra` is missing, the scripts install it automatically with `r2pm`. They try `r2pm -ci r2ghidra` first, and if the local `r2pm` database is not initialized yet they retry after `r2pm -U`.

If `vmlinux-to-elf` is missing, `r2decomp-kernel` creates a local `.venv/` and installs it automatically.

## Kernel Workflow

```bash
./r2decomp-kernel [--kallsyms-file FILE] [--subset-file FILE] [--output-dir DIR] [--kallsyms-remap auto|none|0xOFFSET] [--decompiler pdg|pdc] [--analysis-mode aa|aaa] <kernel-input>
```

Default behavior:

1. Detect the kernel container format.
2. Extract or copy the kernel payload.
3. Rebuild `vmlinux.elf`.
4. If no external `kallsyms` file is provided, generate `*.embedded-kallsyms.txt` from the rebuilt ELF symbol table.
5. Select code symbols, run `radare2`, and write a combined pseudo-C output.

This means the simplest path is now:

```bash
./r2decomp-kernel kernel-01.03.01.89
```

That produces a reconstructed ELF plus an embedded-symbol pseudo-C export under `out/`.

### Decompiler Backend

The default backend is `pdg`, which comes from the `r2ghidra` plugin and usually produces much cleaner structured C than classic `pdc`.

Use the default:

```bash
./r2decomp-kernel --subset-file kallsyms-sitronix-20260704-092316.txt kernel-01.03.01.89
```

Force classic radare2 pseudo-C:

```bash
./r2decomp-kernel --decompiler pdc --subset-file kallsyms-sitronix-20260704-092316.txt kernel-01.03.01.89
```

This is mainly useful for comparison, compatibility, or when you want the old `pdc` behavior.

### Analysis Mode

The default analysis mode is `aa`. This is the faster baseline and is the current default for both scripts.

If you want deeper analysis before decompilation, you can opt into `aaa`:

```bash
./r2decomp-kernel --analysis-mode aaa --subset-file kallsyms-sitronix-20260704-092316.txt kernel-01.03.01.89
```

`aaa` can improve some pseudocode, but it is materially slower on large kernel ELFs.

On the sample kernel in this repo, `aa` took about `35s` median and `aaa` took about `97s` median, so `aaa` was roughly `2.8x` slower. For `sym.sitronix_ts_probe`, the visible `pdg` improvement from `aaa` was mostly better type and temporary inference, not a major control-flow rewrite. See [BENCHMARK.md](./BENCHMARK.md).

### External `kallsyms`

If you have runtime symbols from the live device, pass them explicitly:

```bash
./r2decomp-kernel --kallsyms-file kallsyms-20260704-092316.txt kernel-01.03.01.89
```

That file usually comes from the running kernel:

```bash
cat /proc/kallsyms > kallsyms.txt
```

External `kallsyms` is useful when the running kernel exposes more names than the rebuilt ELF, or when you want runtime naming from the target system.

### Subset File

If you only want a smaller set of functions, pass `--subset-file`:

```bash
./r2decomp-kernel --subset-file kallsyms-sitronix-20260704-092316.txt kernel-01.03.01.89
```

Or combine both:

```bash
./r2decomp-kernel \
  --kallsyms-file kallsyms-20260704-092316.txt \
  --subset-file kallsyms-sitronix-20260704-092316.txt \
  kernel-01.03.01.89
```

`--subset-file` can be either:

- one symbol name per line
- full `kallsyms` lines

When a subset file contains full `kallsyms` lines, only the symbol names are used for filtering. In embedded-symbol mode this is the main point: the addresses from the subset file are ignored and names are looked up in the rebuilt kernel ELF.

If the symbol source contains the same name at multiple addresses, one subset name can expand to multiple decompilations.

### Kallsyms Remap

When using an external runtime `kallsyms` file, addresses may need to be shifted back to file addresses. The script supports:

- `--kallsyms-remap auto`
- `--kallsyms-remap none`
- `--kallsyms-remap 0xOFFSET`

Examples:

```bash
./r2decomp-kernel --kallsyms-file kallsyms.txt --kallsyms-remap auto kernel-01.03.01.89
./r2decomp-kernel --kallsyms-file kallsyms.txt --kallsyms-remap none kernel-01.03.01.89
./r2decomp-kernel --kallsyms-file kallsyms.txt --kallsyms-remap 0x4000000 kernel-01.03.01.89
```

`auto` is the default. It tries anchor symbols such as `_stext` first, then falls back to majority matching across shared symbol names. If confidence is weak, it falls back to no remap instead of forcing a bad offset.

In embedded-symbol mode, remapping is disabled because those addresses already come from the rebuilt ELF.

### Kernel Outputs

Common outputs under `out/...`:

- `*.vmlinux.elf`
- `*.vmlinux-to-elf.log`
- `*.embedded-kallsyms.txt` or `*.normalized.txt`
- `*.report.txt`
- `*.selected-symbols.txt`
- `*.skipped-symbols.txt`
- `*.pdg.c` or `*.pdc.c`
- `*.open-r2.sh`

`*.report.txt` is the main place to check symbol counts, remap details, and why symbols were skipped.

## Binary Workflow

```bash
./r2decomp [--decompiler pdg|pdc] [--analysis-mode aa|aaa] [--output-dir DIR] \
  [--arch auto|arm|thumb|armv7l|aarch64] [--bits auto|16|32|64] \
  [--base auto|ADDRESS] [--raw] [--function NAME@ADDRESS] <binary>
```

Example:

```bash
./r2decomp out/test-default-embedded/kernel-01.03.01.89.vmlinux.elf
```

This script:

1. Detects the architecture of ELF inputs automatically. ARM32/armv7l maps to
   radare2 ARM-32, and AArch64 maps to ARM-64.
2. Detects a raw Cortex-M/Thumb image from a valid vector table at offset zero
   or after the common 0x4000-byte updater header. It maps offset-zero images
   at `0x08000000`. Wrapped images map the whole file at `0x08008000`, placing
   the vector table and executable payload at `0x0800c000`; this preserves the
   metadata-sector/application-sector layout. For any other raw image, specify
   `--raw --arch --bits --base` explicitly.
3. For Cortex-M images, seeds the vector handlers and every aligned in-image
   Thumb function pointer before analysis. This recovers table-driven Klipper
   callbacks that `aa`/`aaa` cannot reach from the updater header or reset path.
4. Runs `radare2` analysis. If deep analysis absorbs a supplied entry point
   into an overlapping function, it repairs that boundary before export.
5. Optionally creates and names known functions supplied as repeatable
   `--function NAME@ADDRESS` arguments. This is useful for a small firmware
   blob where `aa` cannot discover every function without a slower `aaa`.
6. Enumerates discovered functions.
7. Writes a single combined pseudo-C file under the current working directory
   by default.

For example, this reproduces the focused HX711 firmware workflow without a
hand-written radare2 script:

```bash
./r2decomp --output-dir /tmp/hx711-1.7.0 \
  --function hx711s_update_single@0x0800f9cc \
  --function hx711s_sample_task@0x080167ac \
  --function hx711_direct_read@0x0801651c \
  --function hx711_external_update@0x0800f910 \
  ../cc-firmware/stock/strain-gauge-hx711/firmware/upgrade_sg-1.7.0.bin
```

The automatic raw detector is deliberately conservative. A non-ELF file that
does not present a recognizable Cortex-M vector table fails with an explicit
override example rather than being decompiled with a plausible but wrong
architecture or load address.

The default backend is `pdg`. Use `--decompiler pdc` if you want the classic radare2 output instead. The default analysis mode is `aa`; use `--analysis-mode aaa` if you want deeper but slower radare2 analysis first. On the sample kernel here, `aaa` was about `2.8x` slower and mostly changed inferred types/temporaries rather than structure.

Outputs:

- `*.functions.json`
- `*.raw-seeds.r2` for raw Cortex-M inputs
- `*.raw-repair.r2` when named raw functions are supplied (empty if no repair is needed)
- `*.decompile-all-pdg.r2` or `*.decompile-all-pdc.r2`
- `*.pdg.c` or `*.pdc.c`

`r2decomp` does not need a Python virtualenv because it does not rebuild the binary; it only drives `radare2` against an existing binary. By default it writes sidecar files into the directory where you run the command, and `--output-dir` lets you override that.

## Recommended Use

- Use `r2decomp-kernel <kernel-input>` for the default end-to-end kernel path.
- Add `--subset-file` when you only care about one driver or subsystem.
- Add `--kallsyms-file` when you have `/proc/kallsyms` from the live target and want runtime naming or remap support.
- Use `r2decomp <elf>` when you already have the final ELF and want a whole-binary pseudo-C dump.

## TODO

- Support more complex kernel address remapping than a single additive offset when a target uses address translation beyond simple KASLR-style shifts.
