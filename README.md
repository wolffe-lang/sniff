# sniff

A debugger written in [wolf](https://github.com/wolffe-lang/wolf-lang),
for x86-64 Linux and PAX, and macOS arm64. The command language is GDB's;
a Debug Adapter Protocol server is planned for editor integration.

**Status: S0, the map. No debugger commands are implemented.**
The readers come first, then the Linux process core, then macOS and PAX.
[MAP](docs/MAP.md) separates planned capabilities from measured ones.

## Machines and pins

| Role | Hardware / identity |
|---|---|
| Linux development witnesses | x86-64, rootless containers, bounded memory and locked CPU blocks |
| macOS development witness | Apple Silicon arm64, system command-line tools |
| Linux behavioral oracle | GDB; container version and digest are not measured yet |
| macOS behavioral oracle | Apple LLDB 2100.0.16.4, Apple Swift 6.3 |
| Reader oracles | llvm-dwarfdump and readelf, binaries only; pins pending |
| Wolf value oracle | lupin 0.1.59 |
| Bootstrap compiler | wolf 0.2.37, whole release archives pinned by SHA-256 |

`wolf-toolchain.toml` pins archive bytes, including wolf's bundled standard
library and runtime. Nothing is installed globally. Built fixture binaries
and downloads are not committed.

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
