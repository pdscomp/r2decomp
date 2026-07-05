# Auto Decomp Radare2

Two scripts live here:

- `kernel_decomp.sh` for kernel images
- `decomp.sh` for ELF files only

## `kernel_decomp.sh`

Use this when the input might be an Android boot image, `zImage`, `vmlinuz`, a raw kernel blob, or an existing `vmlinux` ELF.

```bash
./kernel_decomp.sh <kernel-input> <kallsyms-file> [subset-file] [output-dir]
```

Arguments:

- `kernel-input`: kernel container or kernel image to analyze
- `kallsyms-file`: symbol list to drive the pseudo-C export
- `subset-file`: optional list of symbol names to export
- `output-dir`: optional destination directory

Behavior:

- auto-detects the input type
- extracts or copies the kernel payload
- rebuilds a usable `vmlinux.elf`
- filters symbols using the provided `kallsyms` file
- writes a combined pseudo-C file for the selected symbols

Outputs are written under `out/` by default, grouped by input and symbol file.

If `r2` is missing, the script prints:

```bash
git clone https://github.com/radareorg/radare2
cd radare2 ; sys/install.sh
```

If `vmlinux-to-elf` is missing, the script creates a local `.venv/` and installs it automatically.

Example:

```bash
./kernel_decomp.sh kernel-01.03.01.89 kallsyms-sitronix-20260704-092316.txt
```

## `decomp.sh`

Use this when you already have an ELF and want a single combined pseudo-C export for every discovered function.

```bash
./decomp.sh <elf-binary>
```

Behavior:

- verifies the input is ELF
- runs `radare2` analysis once
- enumerates discovered functions
- exports pseudo-C for the entire binary into a single `.pdc.c` file beside the ELF

Outputs:

- `*.functions.json`
- `*.decompile-all.r2`
- `*.pdc.c`

Example:

```bash
./decomp.sh out/test-kernel-decomp-elf2/kernel-01.03.01.89.vmlinux.elf
```

## Recommended flow

1. Use `kernel_decomp.sh` to turn the kernel image into a symbolized ELF and a symbol-focused pseudo-C bundle.
2. Use `decomp.sh` on the resulting ELF if you want a full-binary pseudo-C export.
3. For focused driver work, pass a smaller `kallsyms` file or a subset file to `kernel_decomp.sh`.
