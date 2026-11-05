# Sources

Only specifications, manuals, SDK API declarations, organisation-owned
producer documentation and binary oracle observations may inform this work.
No debugger, DWARF library, binutils or OS-kernel implementation was read.
The README contains the standing clean-room allow/never-read lists.

## Consulted for the initial scaffold (2026-11-05)

| Reference | Sections / use |
|---|---|
| [DWARF 5, 2017-02-13](https://dwarfstd.org/doc/DWARF5.pdf) | Introduction; §2.1–2.5 DIEs, attributes, references and expressions, pp. 15–28; §6.2 line-machine introduction and register/file-table model, pp. 148–158; §7.4–7.5 format widths and unit headers, pp. 196–199. These are consultation ranges, not a claim of a completed standards census. |
| [ELF gABI, ELF Header](https://gabi.xinuos.com/elf/02-eheader.html) | ELF64 identification, endianness, table widths and extended section numbering |
| [GDB manual, Breakpoints](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Breakpoints.html) | breakpoint location and management concepts |
| [GDB manual, Continuing and Stepping](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Continuing-and-Stepping.html) | continue, step, next, finish, until and instruction-step contracts |
| [GDB manual, Stack](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Stack.html) | frame selection and variable-lookup context |
| [GDB manual, Examining Data](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Data.html) | print, format selection and memory examination overview |
| wolf-lang `crates/wolf_backend/src/dwarf.rs`, module documentation | DWARF v0 producer coverage and language-tag rationale, not DWARF library implementation |
| wolf-lang `crates/wolf_driver/tests/debug_native.rs` | GDB and LLDB binary acceptance scripts, scalar values, main shim and dSYM behavior |
| fenrir README and `docs/TYPED.md`, `docs/SUBSET.md`, `docs/DIAGNOSTICS.md` | typed side-table contract, current subset, named refusals and exit statuses |
| den README | hardware/pin disclosure and clean-room documentation structure |

## Remaining S0 reading

Complete DWARF 5 §§1–2, 6 and 7; ELF gABI sections, strings and symbols;
GDB breakpoint creation/deletion details, backtrace/frame selection,
`info locals`, `info args`, memory formats and registers. Reader
implementation must also consult DWARF 4 and published Mach-O/dSYM specs.
No reference is marked as read merely because it appears in this list.
