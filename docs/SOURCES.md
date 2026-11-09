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

## Consulted for S1, continued (2026-11-06)

| Reference | Coverage |
|---|---|
| LSB Core 5.0 [Symbol Versioning](https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/symversion.html) | Complete §10.7: the `.gnu.version` array (values 0 and 1 reserved, bit 15 hidden) and the `Elfxx_Verneed`/`Elfxx_Vernaux` layouts used for `.dynsym` version suffixes in `--symbols`. SHA-256 of the page read `982fe1208c76eda09d8619f3907783899e4e73b19c34f3e22314fb36cc8f7f91`. |
| DWARF 5 chapter 7 encoding tables | `src/dump/names.lu` was generated once from the spec text's Tables 7.2-7.30, not from any other reader's tables. |
| AMD64 psABI Figure 3.36 | DWARF register numbers 0-32 for x86-64 register names. |
| Arm AADWARF64 register numbering | 0-31 general registers and 64-95 vector registers; the printed spellings (`W0`, `WSP`, `B8`) are the macOS oracle's, observed in recorded fixtures. |

### Binary observations, not sources

Output layout comes only from the pinned oracles run as binaries:

- Every recorded fixture's complete oracle output, captured once per platform, is the reference for each dump mode.
- `tests/evidence/oracle-probes/` holds synthetic Mach-O inputs and the macOS oracle's complete output on them (unknown-code spellings, string escaping).
- `tests/evidence/vendor-names.json` lists each vendor-range name with the fixture and output line where sniff read the code and the oracle printed the name at the same position.
- `tests/evidence/expression-encoding/` keeps the GNU operation observations.

Where the two oracles print differently (for example `DW_CFA_advance_loc: 4` against `DW_CFA_advance_loc: 4 to 0x100000904`, or `[a, b)` against `(a, b)` in `.debug_loc`), the dump follows the oracle of the container's platform. ELF output follows the Linux oracle and Mach-O output the macOS oracle.

The Linux oracle reads GCC's location-view numbers in `.debug_loclists` as ordinary DWARF 5 entries, because the section has no other structure. A sequential reader that follows DWARF 5 alone prints the same empty lists and fails at the same truncated entry.

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

## Consulted for S2 (2026-11-06)

Man pages fetched from man7.org with curl and read as text; the HTML copies
and their digests are kept by the lane, not committed. Only these were read.

| Page | SHA-256 of the fetched HTML | Used for |
|---|---|---|
| [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html) | `69cd309ece177d54086771701b2085e31cabd14a92484647392bcda468f7bd35` | requests, `PTRACE_O_EXITKILL`/`TRACEFORK`/`TRACEVFORK`, fork event stops (`status>>8 == SIGTRAP\|PTRACE_EVENT_FORK<<8`), `GETEVENTMSG`, the new child starting with SIGSTOP, `DETACH`, errno clearing around `PEEK*`, EIO on invalid memory |
| [wait(2)](https://man7.org/linux/man-pages/man2/wait.2.html) (also covers waitid) | `fe247c4fc91a2dafd978157a46fa2a91fa48b902e643d852e8352d78c4b32fd3` | status macros, `__WALL` |
| [signal(7)](https://man7.org/linux/man-pages/man7/signal.7.html) | `6ab11c524ae2c90beb2dc121ce345e2b54fcca2c008e96672e73e0e933f538db` | signal numbers and default actions (names and descriptions are gdb's, from its own `info signals`) |
| [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html), [proc_pid_mem(5)](https://man7.org/linux/man-pages/man5/proc_pid_mem.5.html), [proc_pid_maps(5)](https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html), [proc_pid_status(5)](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html) | proc `b197c5fa64577269f992d50f60acfd5e0cc3df756644ddd8bd19a02591272a97`; mem `19ef71ade5b244f06592feeec0d2370ab9cdc4b661cc6a007149cd882d2004e5`; maps `3a33949653ca5132a368ed40d74b8e56ea4a8bb6b8f364fe615ddfd994d0be18`; status `1596cd2751b15f9332136b60b28ba8d5c39ebc45e9d75ca8bd1d4d702f7eee43` | `/proc/PID/mem` reads, `maps` line layout for the load base |
| [personality(2)](https://man7.org/linux/man-pages/man2/personality.2.html) | `a416c36b196f40d5b70b3a553f2f3e68e0ddebc4cecc6e7754ea5a1ee3349f86` | `ADDR_NO_RANDOMIZE` |
| [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html) | `ea744b044227c50f852b8cd6165b5e48ed5c8afecf2258710b5e74b06defd309` | exec stop of a traced child |

Where the pages and the probe differ: ptrace(2) asks for word-aligned offsets
only for the USER area; `POKEDATA` at an unaligned text address worked in
every measured run. The core-dump bit of a wait status depends on the
host's core settings, so the probe records statuses with that bit cleared.
The request numbers, register slots and statuses come from
`tools/abi-probe.c` (R-sn02-3), not from header text. gdb's command language
and output shapes are taken from recorded transcripts of the pinned gdb run
as a binary; the GDB manual pages listed under S0 define the command names.

## Consulted for S3 (2026-11-06)

Fetched by curl into the lane's sources directory; the sha256 is of the JSON the page's documentation
endpoint returned.

| source | sha256 | used for |
|---|---|---|
| [com.apple.security.cs.debugger](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.debugger) (`https://developer.apple.com/tutorials/data/documentation/bundleresources/entitlements/com.apple.security.cs.debugger.json`) | `15dbc845196782aed4e0d0349b6979800f9dc5d6780df3d73779ed1a53fdc873` | the debugger entitlement sniff is signed with |
| [Hardened Runtime](https://developer.apple.com/documentation/security/hardened-runtime) (`https://developer.apple.com/tutorials/data/documentation/security/hardened-runtime.json`) | `799ccc6382dfe13d4c732d41981606d5659e56dad6404342643eb37b55ec7bef` | which entitlements let a process take another's task port |

Also read, as interface declarations only, from the macOS SDK, the headers the code cites: `mach/message.h`,
`mach/mach_exc.defs` (the layout of the exception request), `mach/arm/_structs.h` (`ARM_THREAD_STATE64`,
`ARM_DEBUG_STATE64`), `mach-o/loader.h`, `mach-o/compact_unwind_encoding.h`, `sys/ptrace.h`, `sys/signal.h`
(signal numbers) and the spawn flags (`POSIX_SPAWN_START_SUSPENDED`, `_POSIX_SPAWN_DISABLE_ASLR`). From the
Arm ARM: `BRK` (C6.2.40) and the debug state's `MDSCR_EL1.SS` (D2). Apple's arm64 ABI notes for the x29/x30
frame record. The measurements that no page states (what `task_for_pid` accepts on this Mac, the exception
request's byte layout, the status of a forked child that inherits the exception port, the wait interrupted
by SIGCHLD) come from compiled probes of the lane's own children.

Apple's lldb ran as a binary (`lldb -b -s`); its output is the oracle in `tests/evidence/macos-s3`, with the
extraction named in `tools/session-mac.py`.

## Consulted for S4 (2026-11-06)

Linux man pages `ptrace(2)`, `wait(2)`, `proc(5)` and `personality(2)` for the calls the probe in
`tests/pax-probe/probe.c` makes. PAX's kernel and its own notes on its ptrace support are org code, read as
documentation of what PAX answers. The behaviour of the pinned gdb is the oracle, run only as a binary on the
static builds. No debugger's, kernel's or DWARF library's source was read.

## Consulted for S6 (2026-11-08)

Fetched with curl and read as text, each twice and digest-checked; the copies are kept outside the repository.
Only these were read, for both parts of S6 (threads and signals; attach and detach).

| Page | SHA-256 of the fetched HTML |
|---|---|
| GDB manual: [Threads](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Threads.html), [All-Stop Mode](https://sourceware.org/gdb/current/onlinedocs/gdb.html/All_002dStop-Mode.html), [Thread Stops](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Thread-Stops.html), [Signals](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Signals.html), [Attach](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Attach.html), [Kill Process](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Kill-Process.html), [Background Execution](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Background-Execution.html), [Interrupted System Calls](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Interrupted-System-Calls.html) | Threads `368cc901d52d69a2c36dfe6dff9ee0e30615e40e72e86816153094fdd4e06f1f`; All-Stop Mode `fdb51bbcf3cb25bdfee64092e888116d35f6814712dbd681b6b5ac8ce9994bd0`; Thread Stops `88f68cea93f599479e91fa39107705b72cbb9c4473419097085a82e17e38e34f`; Signals `913409f5f5a299b04df8d4f368f668dfb478edaabac1205b929abe92d2f40c5b`; Attach `ad1e902b478d35ca9f404c210c86d0fe9f4b1e38de05b348248bcdb0b71a19c8`; Kill Process `02b0134239ef407087f6f30cd76ba00958b078b518b09c7b1cc4d3e4a6d2f8dc`; Background Execution `69a1cf5e4f9fa8edc837b80580bbba503f1a257a9deeb6ce6b540c40a00a4e43`; Interrupted System Calls `2329ec30663092f7fe143d4f5677cfd55930e4ec7ae5cd3a798cd0088a942a18` |
| man7.org: [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html), [wait(2)](https://man7.org/linux/man-pages/man2/wait.2.html), [signal(7)](https://man7.org/linux/man-pages/man7/signal.7.html), [sigaction(2)](https://man7.org/linux/man-pages/man2/sigaction.2.html), [kill(2)](https://man7.org/linux/man-pages/man2/kill.2.html), [tgkill(2)](https://man7.org/linux/man-pages/man2/tgkill.2.html), [clone(2)](https://man7.org/linux/man-pages/man2/clone.2.html), [prctl(2)](https://man7.org/linux/man-pages/man2/prctl.2.html), [pthreads(7)](https://man7.org/linux/man-pages/man7/pthreads.7.html) | ptrace `69cd309ece177d54086771701b2085e31cabd14a92484647392bcda468f7bd35`; wait `fe247c4fc91a2dafd978157a46fa2a91fa48b902e643d852e8352d78c4b32fd3`; signal `6ab11c524ae2c90beb2dc121ce345e2b54fcca2c008e96672e73e0e933f538db`; sigaction `9c80ae199feabb9faeefd71051df679e0c327ac9d11ca8fa8daaa0d2c9d966bf`; kill `7d953c559068736beefc6f1b246dc25c22509a81439a17f07cf3bcae990b5506`; tgkill `4ffbb2a5206a1778d0d500b6cbca2e38f82b3cdd83314d4f52434ceea9e7ce55`; clone `2ca4447e1dd2bcd221478f495a745cb34cfaeff0cd379e30451be817db16f13a`; prctl `ef698f6c5aab0224e9bf238ea1820160797c15d0adcee8b37fcaac7297866810`; pthreads `0eb05dc85672136493695bb5b8844cd542bf955d7806c1faca8d3eb8fe92dd10` |
| man7.org: [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html), [proc_pid_task(5)](https://man7.org/linux/man-pages/man5/proc_pid_task.5.html), [proc_pid_comm(5)](https://man7.org/linux/man-pages/man5/proc_pid_comm.5.html), [proc_pid_stat(5)](https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html), [proc_pid_status(5)](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html) | proc `b197c5fa64577269f992d50f60acfd5e0cc3df756644ddd8bd19a02591272a97`; task `01a5f0ac2f95ebfd9db435019a055fa26fbf78fef0dd2cd6f384f5aae9f30287`; comm `31e04c6a114f24a1146d38174edb40ef20f7c84c0d17a8604adb036b3479d4b2`; stat `0f04d78946538fd84db1536845abeb236da51a04844989f34ea7ee7cb0b6700f`; status `1596cd2751b15f9332136b60b28ba8d5c39ebc45e9d75ca8bd1d4d702f7eee43` |
| the macOS SDK's `ptrace(2)` (`usr/share/man/man2/ptrace.2`, macOS 26.4) | `7891afb4009dd49d63420f48e3dc3f7bc9a936b44b78a9291830a97607cad94c` (the file) |

Used for: thread events and all-stop (`PTRACE_O_TRACECLONE`, `__WALL`, `tgkill`), signal stops and their
delivery, a thread's name and the tracer's pid (`comm`, `TracerPid`), a process's threads (`/proc/PID/task`) and
its state (`State:` in `status`, which the attach rows' harness waits on), `PTRACE_ATTACH` and `PTRACE_DETACH`
on Linux and PAX; on macOS `PT_ATTACHEXC`, `PT_THUPDATE` and `PT_DETACH`, whose need for a stopped process
(EBUSY) set sniff's detach order. Also read, as interface declarations only, from the macOS SDK: `task_for_pid`,
`task_threads`, `thread_info` (`THREAD_IDENTIFIER_INFO`), `task_suspend` and `task_resume`, and
`task_set_exception_ports`. The orders the man pages leave open (when `PT_DETACH` succeeds under
`PT_ATTACHEXC`, how a SIGKILL ends a process attached to) come from compiled probes, run against sleepers started for
them; gdb ran only as the pinned binary and lldb only as the system binary.
