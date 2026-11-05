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

## Consulted for S1 (2026-11-05)

A dedicated standards-only reading pass covered the sources below. Its scope
is stated explicitly; downloading a document was not counted as reading it.

| Reference | Coverage |
|---|---|
| [DWARF 5](https://dwarfstd.org/doc/DWARF5.pdf) | Whole February 13, 2017 document: all 477 PDF pages, front matter, chapters 1–7, appendices A–H and index. Sequential extracted text included tables/examples; section-relationship diagrams were also rendered. SHA-256 `cc9a9b49163aa7c65923b45ade0df6f5dff5ee50ecf8e5938c03ffbfa06a25e4`. |
| [DWARF 4](https://dwarfstd.org/doc/DWARF4.pdf) | Comparison reading: §§1.1–1.4, 2.6.2, 2.16–2.19, 5.5.6, 5.9, 6.1.1–6.1.2, 6.2.4, 6.2.5.3, 6.3, 7.2–7.5.4, 7.7.3, 7.22–7.25 and adjacent tables. Not a whole-document claim. SHA-256 `b0b88aab5cd07e3d9d45cc6780b74c0bac418c7d0b295e85f8a56b436b61c506`. |
| [Official DWARF 5 errata](https://dwarfstd.org/errata-dwarf5.html) | Entire errata page, file-zero issue 210713.1 and the committee's file-number discussion. |
| [ELF gABI](https://gabi.xinuos.com/elf/) | Foreword, textual chapters 1–8, OSABI appendix and revision history; machine appendix entries for x86-64/AArch64. The site mixes 4.3 DRAFT and older loading/dynamic pages. |
| [System V AMD64 psABI](https://gitlab.com/x86-psABIs/x86-64-ABI/-/jobs/artifacts/master/raw/x86-64-ABI/abi.pdf?job=build) | ABI 1.0, March 12, 2025; §§3.6–3.7, 4.1–4.2.4, including EH_FRAME tables, and §6.2 GetIP/GetIPInfo excerpts. SHA-256 `19f346cc723dbeb6ad80494614291f4e85aba3caca48dcfd537d33f82af6d6ac`. |
| LSB Core 5.0 [DWARF extensions](https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/dwarfext.html) and [Exception Frames](https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/ehframechpt.html) | Complete §§10.5–10.6. |
| [Arm AADWARF64](https://github.com/ARM-software/abi-aa/blob/main/aadwarf64/aadwarf64.rst) | 2026Q3, November 3, 2026; technical text from status/history through the end, including register maps, CFA, CIE defaults, CFI/expression extensions and vector material. Standards text only. |
| [Arm AAELF64](https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst) | Selected ELF class/header, sections, strings, symbols/mapping symbols, relocation introduction and static/TLS data relocation clauses. Not a whole-document claim. |
| [Apple Mach-O overview](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/MachOOverview.html) | Complete published overview. The retired MachORuntime reference URL returned 404; the overview and allowed SDK headers supplied structural documentation. |
| macOS 26.4 SDK `mach-o/loader.h`, `nlist.h`, `fat.h`, `compact_unwind_encoding.h` | Loader header/load-command/segment/section/symbol/UUID/linkedit declarations and format comments; complete other named headers. These are interface specifications, including their format-documentation comments. No compact-unwind decoder is in S1. |
| Apple [symbolication](https://developer.apple.com/documentation/xcode/adding-identifiable-symbol-names-to-a-crash-report) and [missing debug symbols](https://developer.apple.com/documentation/xcode/locating-a-missing-debug-symbol-file) | Both articles, obtained through Apple's official documentation data endpoints: inner dSYM DWARF path and architecture-specific UUID matching. |
| SDK llvm-nm and llvm-dwarfdump | Pinned binary `--version`/`--help` and labelled fixture output observations only; no implementation source. |
| Wolf language specification and tool help | Numeric casts/shifts, byte/list operations, parameter grammar, OS primitive signatures, module rules and pinned compiler command interfaces. |

### Consequences and compatibility boundaries

- DWARF32/64 offsets are independent of address size and container class.
  Initial lengths exclude their own encoding; reserved initial-length values
  are not ordinary lengths. Units, blocks and tables retain parent bounds.
  Appendix C's illustrative LEB algorithms do not protect against malformed
  encodings; bounded work and overflow checks are the reader's responsibility.
- Unit-relative references start at the first byte of the unit header;
  ref_addr has section-offset semantics. Reference validation checks actual
  DIE starts. Legal recursive types require cycle-aware traversal, not a
  blanket ban on reference cycles.
- Address/string bases select the first table entry after its header.
  Range/location offset entries are relative to the offset-array start.
  Known forms allow unknown attributes to be preserved structurally; unknown
  forms or operation layouts do not permit guessed byte skips.
- Version 4 and 5 have different unit headers, range/location formats and
  line-directory/file conventions. A line program's version is independent
  of its CU version. End-sequence emits a terminal address then resets state.
- The DWARF 5 file-zero ambiguity remains a compatibility boundary: §2.14
  assigns decl_file=0 no file, while §6.2.4 indexes the primary file at zero;
  the initial file register is 1. [Issue 210713.1](https://dwarfstd.org/issues/210713.1.html)
  resolves this for DWARF 6, not as a silent rewrite of every DWARF 5 unit.
  Producer-specific behavior needs labelled binary evidence.
- Apply the official errata: indirect forms may repeat; an indirect
  implicit_const takes its value from info, not the abbreviation; CFI
  remember_state includes the CFA rule; call_origin is a reference; separate
  tables are contiguous. Split/supplementary DWARF remains a named refusal.
- ELF sections and virtual addresses are different coordinate systems.
  Extended section counts/indexes use section zero. NOBITS occupies no file
  bytes. Symbol names use the symbol table's linked string table, and strings
  may share suffixes. Compressed sections remain a named refusal.
- `.debug_frame` has an all-ones CIE ID and section-relative CIE offsets;
  `.eh_frame` has zero CIE IDs and fixed four-byte backwards CIE distances
  from the pointer field. Extended EH lengths do not change that field width.
  FDE ranges are byte counts, not relative pointers. Parse augmentation
  operands in string order. Concrete AMD64 EH tables plus LSB take precedence
  over contradictory introductory AMD64 prose about CIE IDs/default widths.
- The core sources do not fully specify the EH indirect modifier, all
  historical CIE/signal augmentations, or GNU/APPLE/LLVM extension semantics.
  Such support needs separately labelled binary observations or additional
  permitted documentation, never implementation-source inference.
  GNU_args_size is an exception: AMD64 and LSB specify its ULEB operand.
- AArch64 register/CFI defaults are ABI-specific. The 2026Q3 Alpha PAC-state
  additions are not automatically assumed to describe deployed Darwin data.
- Mach-O command arrays are bounded by both ncmds and sizeofcmds; section
  names are fixed-width byte fields. A section_64 file offset is still u32.
  Symbol ordinals span sections in load-command order. The dSYM inner path is
  `Contents/Resources/DWARF/<binary-name>`; appropriate architecture UUIDs
  must match. Compact-unwind presence is independent of empty DWARF CFI.

## Incidental exposure

On 2026-11-05, the standards-reading pass's broad web search returned a
search-result snippet linked to a libunwind header. The implementation link
was not opened; neither the snippet nor that source was used as authority or
as implementation input. It is quarantined from this work. An unwinder's
implementation source is outside the clean room, regardless of whether the
standing list names that particular library. Future implementation-linked
search results are likewise not opened and are recorded here if exposed.

The same pass read a commented illustrative permutation-encoding algorithm
inside Apple's published `mach-o/compact_unwind_encoding.h`. This is
**in-ruling interface documentation**: the permitted SDK headers include
comments describing their formats. It is not treated as forbidden
implementation-source exposure. Compact unwind nevertheless remains S3's
subject; S1 refuses it by name and implements no compact-unwind decoder.
