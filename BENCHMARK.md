# Benchmark

This repo includes a simple `aa` vs `aaa` benchmark from the sample kernel ELF:

- Input ELF: `out/test-sitronix-pdg/kernel-01.03.01.89.vmlinux.elf`
- Radare2 version: `6.1.9`
- Decompiler comparison target: `sym.sitronix_ts_probe`

## Analysis Time

Single-pass wall clock:

- `aa`: `36.461s`
- `aaa`: `98.951s`
- `aaa / aa`: `2.71x`
- absolute increase: `62.490s`

Three-run benchmark:

- `aa` runs: `34.992s`, `34.971s`, `35.052s`
- `aa` median: `34.992s`
- `aaa` runs: `96.468s`, `96.956s`, `98.997s`
- `aaa` median: `96.956s`
- `aaa / aa` median ratio: `2.77x`

## Pseudocode Quality

Files to compare:

- `pdc + aa`: `out/test-sitronix-samples/sitronix_ts_probe.pdc.aa.c`
- `pdg + aa`: `out/test-sitronix-samples/sitronix_ts_probe.pdg.aa.c`
- `pdg + aaa`: `out/test-sitronix-samples/sitronix_ts_probe.pdg.aaa.c`

Observed result on this kernel:

- `pdg` is a clear improvement over `pdc`
- `aaa` did not materially improve control-flow structure over `pdg + aa`
- the visible `aa` vs `aaa` differences were mostly variable names and inferred types

Practical takeaway:

- default to `pdg` with `aa`
- try `aaa` only when a specific function still looks ambiguous and the extra analysis time is acceptable
