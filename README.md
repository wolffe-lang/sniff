# sniff

A debugger written in [wolf](https://github.com/wolffe-lang/wolf-lang),
for x86-64 Linux and PAX, and macOS arm64. The command language is GDB's;
a Debug Adapter Protocol server is planned for editor integration.

**Status: S2, the core on Linux x86-64.** `sniff -batch -x SCRIPT PROG` starts PROG
under `ptrace(2)` and debugs it with gdb's command language (breakpoints,
stepping, frames, values, registers), held to transcripts of the pinned gdb
and to lupin's values; `sniff dump` still prints the S1 reader views. macOS
and PAX backends are S3 and S4. [MAP](docs/MAP.md) separates planned
capabilities from measured ones.

## Machines and pins

| Role | Hardware / identity |
|---|---|
| Linux development witnesses | x86-64, rootless containers, bounded memory and locked CPU blocks |
| macOS development witness | Apple Silicon arm64, system command-line tools |
| Linux behavioral oracle | GDB 15.1 (Ubuntu 15.1-1ubuntu1~24.04.1), binary SHA-256 pinned |
| macOS behavioral oracle | Apple LLDB 2100.0.16.4, Apple Swift 6.3 |
| Reader oracles | Ubuntu llvm-dwarfdump 18.1.3 and readelf 2.42, binary SHA-256 pinned; SDK llvm-dwarfdump on macOS |
| macOS symbol oracle | SDK llvm-nm, Apple LLVM 21.0.0; version and binary SHA-256 pinned |
| C producers | GCC 13.3.0 and clang 18.1.3 on Linux; Apple clang 21.0.0 on macOS |
| Wolf value oracle | lupin 0.1.59 |
| Bootstrap compiler | wolf 0.2.37, whole release archives pinned by SHA-256 |

`wolf-toolchain.toml` pins archive bytes, including wolf's bundled standard
library and runtime. `sniff-oracle.toml`, `ci/packages.txt` and
`ci/oracle-binaries.lock` bind the Linux image recipe, its complete package
closure and the five oracle/producer binaries. The macOS symbol oracle is
also pinned in `sniff-oracle.toml`. The symbol guard checks `--version` and
SHA-256 before fixture work on either platform; a mismatched PATH binary is
refused by name. Nothing is installed globally. Built fixture binaries and
downloads are not committed.

## Use

```sh
wolf build src/main.lu -o target/sniff
target/sniff dump --debug-info prog            # or prog.dSYM on macOS
```

Modes: `--debug-info`, `--debug-abbrev`, `--debug-line`, `--debug-addr`,
`--debug-str-offsets`, `--debug-ranges`, `--debug-rnglists`, `--debug-loc`,
`--debug-loclists`, `--eh-frame`, `--debug-frame` and `--symbols`. ELF output
follows the Linux oracle (`llvm-dwarfdump-18`, and `readelf --symbols --wide`
for symbols). Mach-O output follows the SDK `llvm-dwarfdump` and `llvm-nm`.
The two oracles differ in a few spellings, and each container format keeps its
platform's. Malformed or unsupported input is refused by name on standard
error with status 1. Compact unwind, split DWARF and compressed sections are
among the refusals.

## Build and measure

S0 supplies the reproducible corpus builder,
producer-separated DWARF census, scripted debugger capture and comparison,
and lupin's statement-boundary local-value recorder. The corpus contains five
wolf programs and six C programs. Linux builds every C program with GCC and
clang at `-g -gdwarf-5 -O0` and `-O2`; macOS uses its SDK clang. Wolf 0.2.37
emits DWARF in its default tier and has no `-g` option.

```sh
bash tools/gate unit                 # parser/comparator/tier contracts and saved transcript replay
                                     # (macos and linux add reader rows, hostile inputs and the dump matrix)
bash tools/gate macos                # SDK tools; downloads only pinned wolf/lupin archives
SNIFF_CPUS=0 bash tools/in-container  # Docker; bounded Linux fixture and oracle gates
```

The Linux wrapper also accepts `SNIFF_ENGINE=podman`. Choose CPUs permitted by
the execution environment. Shared development machines require their CPU and
memory gates before these commands. The full Linux container uses 12 GiB;
short light-slot steps can pass a lower explicit memory limit. Debuggers only
launch fixtures created by the harness, never attach to unrelated processes.

Each fixture is rebuilt twice at the same paths and every binary/object/dSYM
byte is hashed without normalization. C object mtimes and source dates are
fixed; Mach-O links use `-reproducible` while retaining UUIDs. Session records
retain parsed observations and name all address, PID, timestamp and lane-root
normalizations. Frame assertions include source coordinates so the C entry
shim cannot stand in for a missing wolf frame. Lupin traces describe state
**after** a statement; the scalar join explicitly compares that state with the
debugger stopped **before** the next statement.

Hosted CI's macOS job runs the oracle-free rows only: units, the reader rows
natively and checked, the sniff build, fixture builds, hostile inputs and lupin
values. No hosted runner image carries the pinned Apple LLVM 21.0.0 `llvm-nm` and
`llvm-dwarfdump` binaries (by SHA-256), so there the symbol pin, the dump
matrix, the census, the live transcript and the steps that consume it print
`SKIP <step> reason=...` by name. They run, pins and refusals unchanged, in the
Mac's local gauntlet record. The skip keys on `SNIFF_HOSTED_MACOS_CI=1`, which
only that job sets; Linux rows never skip.

Unlabelled PRs run the cheap `tier local` unit/replay gate. `ci` requests
Linux `tier pr`; `full-matrix` requests Linux plus macOS `tier full`. Nightly,
relevant trunk pushes and a manual dispatch without a job filter run the full
release gate. Saved oracle observations and passing harness selftests are not
sniff command parity; the S2 rows run sniff itself (`tools/session.py`).

## Clean room

May be read: DWARF 5 and 4; the ELF gABI; the System V x86-64 psABI and
AArch64 ELF and DWARF ABIs; Intel SDM and Arm ARM architecture documentation;
Linux manual pages; the GDB manual including its remote protocol appendix;
the DAP specification; QEMU gdbstub documentation; Apple's published Mach-O
and dSYM documentation and macOS SDK API declarations.

Never read: source of GDB, gdbserver, LLDB, LLVM DWARF libraries, libdwarf,
elfutils/libdw, gimli, delve, rr, radare2, binutils, XNU or another OS kernel.
Oracle tools are run only as binaries, not inspected as implementations.
Organisation-owned code may be consulted: wolf's DWARF emitter as producer
documentation, fenrir's front end, PAX, and lupin's black-box behavior.
[SOURCES](docs/SOURCES.md) records documentation actually consulted.

## Licence

GPL-3.0-or-later with the wolf Training Data Permission.
See `LICENSE` and `LICENSE-TRAINING-DATA`.
