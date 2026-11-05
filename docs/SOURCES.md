# Sources

Only specifications, manuals, SDK API declarations, organisation-owned
producer documentation and binary oracle observations inform this work.
No debugger, DWARF library, binutils or OS-kernel implementation was read.
The README contains the standing clean-room allow/never-read lists.

## Consulted for S0 (2026-11-05)

The complete DWARF chapters below were reviewed through a standards-only
reading pass. Implementation conclusions use these clauses, not another
reader's implementation.

| Reference | Sections / use |
|---|---|
| [DWARF 5, 2017-02-13](https://dwarfstd.org/doc/DWARF5.pdf) | Complete chapters 1 (§§1.1–1.7, pp.1–14), 2 (§§2.1–2.24, pp.15–58), 6 (§§6.1–6.4.4, pp.135–182) and 7 (§§7.1–7.33, pp.183–250), including encoding tables. In particular: DIE/forms §7.5, LEB128 §7.6, expressions/locations §§2.5–2.6, line program §6.2, CFI §6.4, indexed tables §§7.26–7.29. |
| [ELF gABI, ELF Header](https://gabi.xinuos.com/elf/02-eheader.html) | ELF64 identification, endianness, table widths and extended numbering |
| [ELF gABI, Sections](https://gabi.xinuos.com/elf/03-sheader.html) | section headers, NOBITS, link/info fields, compressed-section metadata and extended indexes |
| [ELF gABI, String Table](https://gabi.xinuos.com/elf/04-strtab.html) | byte indexing, zero terminators, empty tables and suffix sharing |
| [ELF gABI, Symbol Table](https://gabi.xinuos.com/elf/05-symtab.html) | ELF64 symbol fields, binding/type/visibility, undefined/absolute/common indexes |
| [GDB manual, Breakpoints](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Breakpoints.html), [Set Breaks](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Set-Breaks.html), [Delete Breaks](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Delete-Breaks.html) | function, file:line and *address locations; breakpoint/location numbering, conditions, temporary stops, clear versus delete |
| [GDB manual, Continuing and Stepping](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Continuing-and-Stepping.html) | continue, step, next, finish, until and instruction-step contracts |
| [GDB manual, Stack](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Stack.html), [Backtrace](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Backtrace.html), [Selection](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Selection.html), [Frame Info](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Frame-Info.html) | frame 0 is the current activation, callers increase in level; up/down; selected-frame context; locals and arguments |
| [GDB manual, Examining Data](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Data.html), [Memory](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Memory.html), [Registers](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Registers.html) | print, x/nfu count/format/size defaults, general/all register displays, selected-frame register reconstruction |
| macOS `ld(1)` | `-reproducible`, OSO debug-map paths and hash-derived UUIDs; do not remove LC_UUID to hide nondeterminism |
| wolf-lang `crates/wolf_backend/src/dwarf.rs`, module docs; `src/lib.rs`, DebugTy/DebugSink declarations | DWARF v0 producer coverage, scalar catalogue, source coordinates, forced spill locations and language-tag rationale; no DWARF-library source |
| wolf-lang `crates/wolf_driver/tests/debug_native.rs` | GDB and LLDB binary acceptance scripts, scalar values, main shim and dSYM behavior |
| lupin `--help`, `--version`, and `docs/manual/06-place-trace.md` | binary statement/tail trace, per-place scalar values and explicit post-statement semantics |
| fenrir README and `docs/TYPED.md`, `docs/SUBSET.md`, `docs/DIAGNOSTICS.md` | typed side-table contract, current subset, named refusals and exit statuses |
| den README | hardware/pin disclosure and clean-room documentation structure |

## Reader cautions

DWARF's offset width is independent of target address width (§7.4). CFI in
DWARF 5 specifies `.debug_frame`, not the ABI's `.eh_frame`. A reader must
consult the published unwind ABI before decoding the latter's encoded pointers
and CIE references. Generic expression arithmetic wraps at target address
width; resource limits are not proof of malformed input.

The 2017 text initializes the line machine's file register to 1 (p.153), while
its v5 file table begins at 0 (p.158). Preserve the distinction and consult
published errata rather than silently inventing a convention. Other textual
inconsistencies to resolve from specifications before implementation include
DW_IDX_parent's description versus Table 6.1, and DW_CFA_register's operand
label versus its prose.

## Next-milestone references, not yet read

DWARF 4; Mach-O/dSYM and SDK API declarations; architecture register/unwind
ABIs and the published `.eh_frame` exception-frame specification. These are
required before S1/S3 implementation, not claimed as completed S0 reading.
