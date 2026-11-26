# sniff

A debugger written in [wolf](https://github.com/wolffe-lang/wolf-lang),
for x86-64 Linux and PAX, and macOS arm64. The command language is GDB's;
`sniff --dap` is a Debug Adapter Protocol server on standard input and output: on Linux it launches a program (with
its working directory and environment) or attaches to a running process by its pid or to a remote stub such as
QEMU's gdbstub, and debugs it (breakpoints by line or function, with conditions and hit counts; stepping by line or
instruction; threads, stack traces, scopes, variables and their children; `evaluate`, whose repl runs the command
language; `readMemory`; `pause`, `terminate` and `disconnect`), its answers held to the pinned gdb's own DAP
transcripts; macOS follows.

**Status: milestones S0 to S6 are met on Linux x86-64, macOS arm64 and PAX; core files (S7) are read on Linux, at PAX's console and on macOS; cores PAX writes itself come next. S8's remote client is in, and so is its stub, `sniff-server`, on Linux and PAX.** `sniff -batch -x SCRIPT PROG` starts PROG
(under `ptrace(2)` on Linux; as a suspended child with its task port and exception port on macOS) and debugs it with gdb's command language (breakpoints,
stepping, frames, values, registers, watchpoints, threads (all-stop) and signals, `list` and `help`); `attach PID`, `detach` and
`sniff -p PID PROG` take a running process instead, and `sniff -batch -x SCRIPT PROG CORE` (or `-c CORE`, or `core-file CORE`) reads
a core file as a stopped program: an ELF core of a Linux program, or on macOS a Mach-O core lldb wrote. On Linux,
`target remote HOST:PORT` debugs a target over the GDB remote protocol (S8): held so far to QEMU's gdbstub on PAX's
console kernel at one processor (reads, breakpoints including `hbreak`, stepping, the interrupt, watchpoints, `detach`,
`disconnect` and `kill`); assignment over a remote target, and the Mac's kernel rows, come later. It is held to transcripts of the pinned gdb
and, on macOS, to Apple's lldb (facts) and to lupin's values; `sniff dump` still prints the S1 reader views.
On PAX it is a static program of the dev image and debugs static programs with PAX's ptrace (see notes/sn04-sniff-on-pax.md). [MAP](docs/MAP.md) separates planned
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
| Wolf value oracle | lupin 0.1.60 |
| Bootstrap compiler | wolf 0.2.38, whole release archives pinned by SHA-256 |
| Remote targets (S8) | QEMU 11.1.2, built from its release tarball in the Linux image and on the Mac, binary SHA-256 pinned; gdbserver 15.1, the stub's reference, run only as a binary |

`wolf-toolchain.toml` pins archive bytes, including wolf's bundled standard
library and runtime. `sniff-oracle.toml`, `ci/packages.txt` and
`ci/oracle-binaries.lock` bind the Linux image recipe, its complete package
closure and the seven oracle, producer and target binaries. The Linux image uses a dated
archive snapshot and a digest-checked certificate bootstrap; an index failure
stops the build. The bootstrap is the snapshot's own `ca-certificates`
package, kept in `ci/bootstrap/` by SHA-256, so the image build fetches
nothing before apt. The macOS symbol oracle is
also pinned in `sniff-oracle.toml`. The symbol guard checks `--version` and
SHA-256 before fixture work on either platform; a mismatched PATH binary is
refused by name. Nothing is installed globally. Built fixture binaries and
downloads are not committed, apart from that one package.

## Use

```sh
wolf build src/main.lu -o target/sniff
target/sniff dump --debug-info prog            # or prog.dSYM on macOS
target/sniff --version                         # sniff 0.1.0; src/wolf.pkg names the number
```

The stub serves one program to one client over the GDB remote protocol (S8):

```sh
wolf build src/sniff_server.lu -o target/sniff-server
target/sniff-server :1234 prog [args...]           # listens on 127.0.0.1:1234; then `target remote :1234` in gdb or sniff
target/sniff-server --non-loopback 0.0.0.0:1234 prog
```

**The protocol has no authentication: whoever connects to the port controls the program, and can read and write its
memory and registers.** So the stub listens on the loopback address unless the address is given and is not a loopback
one, and then only with `--non-loopback`, asked for by name; without it such an address is refused with that warning.
It serves one client at a time: a second client gets an error reply naming that and is closed. It starts the program
stopped at its first instruction and ends when its client does: `kill`, or the client going away, kills the program;
`detach` takes out every breakpoint and watchpoint and lets the program run on. It offers its own target description, software and hardware breakpoints, watchpoints, the
registers (the x87 and SSE ones written back on Linux; PAX refuses those writes, and the stub says so with an error
reply), threads in all-stop with their names, and the interrupt; not multiprocess, Host I/O or non-stop. Its rows hold
it to the pinned gdbserver run beside it on Linux, and on PAX's console under KVM (see docs/MAP.md).

Modes: `--debug-info`, `--debug-abbrev`, `--debug-line`, `--debug-addr`,
`--debug-str-offsets`, `--debug-ranges`, `--debug-rnglists`, `--debug-loc`,
`--debug-loclists`, `--eh-frame`, `--debug-frame`, `--symbols` and, for a core
file, `--notes`. ELF output follows the Linux oracle (`llvm-dwarfdump-18`, and
`readelf --symbols --wide` and `readelf --notes --wide`). Mach-O output follows the SDK `llvm-dwarfdump` and `llvm-nm`.
The two oracles differ in a few spellings, and each container format keeps its
platform's. Malformed or unsupported input is refused by name on standard
error with status 1. Compact unwind, split DWARF and compressed sections are
among the refusals.

## Build and measure

S0 supplies the reproducible corpus builder,
producer-separated DWARF census, scripted debugger capture and comparison,
and lupin's statement-boundary local-value recorder. The corpus contains five
wolf programs and six C programs. Linux builds every C program with GCC and
clang at `-g -gdwarf-5 -O0` and `-O2`; macOS uses its SDK clang. Every wolf
program is built with `-g`: wolf 0.2.38's default tier describes its source
types in DWARF, and `-g` adds a non-allocated `.debug_frame`, so wolf frames
unwind through CFI.

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
launch fixtures created by the harness, and attach only to the sleeper fixture the harness starts as its
own child, never to an unrelated process.

Each fixture is rebuilt twice at the same paths and every binary/object/dSYM
byte is hashed without normalization. C object mtimes and source dates are
fixed; Mach-O links use `-reproducible` while retaining UUIDs. Session records
retain parsed observations and name all address, PID, timestamp and lane-root
normalizations. Frame assertions include source coordinates so the C entry
shim cannot stand in for a missing wolf frame. Lupin traces describe state
**after** a statement; the scalar join explicitly compares that state with the
debugger stopped **before** the next statement.

On macOS, `tools/sign-sniff.sh` ad-hoc signs sniff with the debugger entitlement
(`com.apple.security.cs.debugger`); the fixtures are signed with `get-task-allow`. Neither needs
`sudo` or a change to `DevToolsSecurity`. A target without `get-task-allow` is refused by name.

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
release gate; a trunk push leaves out the macOS job when a run at the same
commit, over the same tree, already ran it green, and names that run. Saved
oracle observations and passing harness selftests are not
sniff command parity; the S2 rows run sniff itself (`tools/session.py`).

## Clean room

May be read: DWARF 5 and 4; the ELF gABI; the System V x86-64 psABI and
AArch64 ELF and DWARF ABIs; Intel SDM and Arm ARM architecture documentation;
Linux manual pages; the GDB manual including its remote protocol appendix;
the DAP specification; QEMU gdbstub documentation; Apple's published Mach-O
and dSYM documentation and macOS SDK API declarations.

Never read: source of GDB, gdbserver, LLDB, LLVM DWARF libraries, libdwarf,
elfutils/libdw, gimli, delve, rr, radare2, binutils, XNU or another OS kernel,
QEMU (beyond the build-script lines its build needs, and never its `gdbstub/`
or `target/` directories), or any other implementation of the remote protocol.
Oracle tools are run only as binaries, not inspected as implementations.
Organisation-owned code may be consulted: wolf's DWARF emitter as producer
documentation, fenrir's front end, PAX, and lupin's black-box behavior.
[SOURCES](docs/SOURCES.md) records documentation actually consulted.

## Licence

GPL-3.0-or-later with the wolf Training Data Permission.
See `LICENSE` and `LICENSE-TRAINING-DATA`.
