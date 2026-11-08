# Architecture map

The table below is the intended module boundary, not an implementation claim.
The immutable pre-code prediction is `tests/prediction.json`; the measured
frontier and reader scope below refine it without rewriting that prediction.

| Stage | Modules / responsibility | Acceptance |
|---|---|---|
| S0 | fixture builders, binary oracle adapters, transcript comparison, census | digest-bound builds, named red-first harness failures |
| S1 | bounded bytes, ELF64, Mach-O64/dSYM, DWARF units/forms/lines, symbols, ranges/locations, CFI | dump modes byte-identical to the pinned reader oracle |
| S2 | Linux x86-64 process control, breakpoint patching, source stepping, unwind, scalar values, GDB command parser | scripted GDB sessions and lupin local-value agreement |
| S3 | macOS arm64 task/exception ports, BRK, register access, compact unwind, Mach-O + dSYM by UUID, signing | S2 commands against lldb facts, lupin, and the Linux goldens where both answer alike |
| S4 | PAX process backend, static dev-image packaging | S2 console session agrees with Linux after named normalization |
| S5 | hardware watchpoints, conditions, expressions, aggregate presentation | pinned fenrir front end; every unsupported construct refused by name |
| S6 | all-stop threads, signals, attach/detach | per-platform scripted sessions |
| S7 | ELF and Mach-O core readers | process-independent replay |
| S8 | remote serial client and small remote process stub | QEMU gdbstub and remote-process sessions |
| S9 | Debug Adapter Protocol server | recorded editor-client exchange |

## Reader invariants

DWARF format width is not target address width. Every unit, contribution,
attribute block and string has a containing byte bound; checked arithmetic
precedes allocation and offset arithmetic. Abbreviation references and DIE
references must remain within their specified domains. Unsupported encodings
are named errors, not a guessed byte skip.

Line-table sequences reset independently; an `end_sequence` row is not a
source statement. Preserve columns, discriminator, `is_stmt`, prologue and
epilogue flags, and the original row order. DWARF 4 and 5 use different file
and directory-table conventions.

CFI from the linked runtime is not proof of CFI for a wolf function. The census
must attribute units to producers and frame ranges to owning functions.
A base-type DIE does not imply an aggregate can be printed.

## Expressions

S5 will vendor a pinned, provenance-marked copy of fenrir's front end.
Its typed side tables are keyed by AST node ID; consumers must check the
nonempty diagnostic code before consuming partial tables. Its current F1
core has no indexing, dereference, casts, floating-point literals, methods,
generics, enum or list expressions. Reusing that core is not permission to
silently accept those constructs: named refusals remain visible.

## Measured fixture frontier

The corpus has five wolf programs (scalars, nested calls, loops, shared module
names and scalar types) and six C programs (aggregates, arrays, pointers,
recursion, inlining and threads). The build matrix is 17 Mach-O binaries and
29 ELF binaries. Each recorded build has two identical SHA-256 maps covering
its executable, object and dSYM files where applicable. The complete per-file
forms, attributes, type tags, expressions and line opcodes are in
`tests/evidence/{macos,linux}/census.json`; build digests and producer versions
are beside them. Binary files are not committed.

| Producer / artifact | Units and versions | Important observed encodings |
|---|---|---|
| wolf-owned ELF units | DWARF 4; one CU, or three for shared-name | addr, exprloc, ref4, sec_offset, string, udata; base_type/subprogram/formal_parameter/variable; fbreg and reg6 |
| wolf-owned dSYM units | DWARF 4; same source CU counts | dsymutil rewrites inline strings to strp; fbreg and reg29; linked line sequences can be coalesced |
| Bundled runtime | separate Rust/LLVM DWARF 4 units; counts vary with linking | many more tags, forms and location operations than wolf emits; never counted as wolf coverage |
| GCC and clang C, Linux | DWARF 5, O0 and O2 | strp/string/line_strp, addrx, strx1, loclistx, rnglistx, implicit_const, register/piece/entry_value/stack_value locations |
| Apple clang C, dSYM | DWARF 5, O0 and O2 | addrx, strx, implicit_const, exprloc and register/composite locations |

Wolf's own line programs use statement flags, prologue markers, standard and
special opcodes and explicit sequence termination. The census attributes
executed opcodes through each CU's stmt_list offset: merely declaring an
opcode's length in a line header does not count as using it.

Linux C binaries have `.eh_frame`; the measured macOS C binaries have neither
`.eh_frame` nor `.debug_frame` FDEs. This is not a claim that Mach-O lacks
compact unwind metadata. Wolf binaries have runtime `.eh_frame`, but no
measured FDE fully covers any wolf-owned function range. The successful
source backtraces must not be presented as proof of compiler CFI.

## S1 reader scope from the census

Start with bounded ELF64 little-endian x86-64 and Mach-O64 little-endian arm64
containers, symbols and UUID-matched dSYM companions. Decode DWARF 4 and 5,
keeping DWARF32/64 contribution widths separate from address size. Implement
abbreviations and DIEs, including zero-byte flag_present and implicit_const;
inline and referenced strings, including line_strp and indexed strings;
address tables; versioned line programs; DWARF 4 ranges/locations and DWARF 5
rnglists/loclists. The indexed forms are measured requirements, not speculative
future work.

Decode CIE/FDE tables in `.eh_frame` and `.debug_frame` from their respective
published formats. Dump decoding must cover the observed register, CFA,
frame-base, piece, stack-value and entry-value operations without pretending
that S1 evaluates an inferior's values. Runtime units are part of dump coverage
even though they do not establish wolf language coverage.

The first dump modes are `--debug-info`, `--debug-abbrev`, `--debug-line`,
`--debug-addr`, `--debug-str-offsets`, `--debug-ranges`, `--debug-rnglists`,
`--debug-loc`, `--debug-loclists`, `--eh-frame` and `--debug-frame`. Each output
is compared byte-for-byte with its platform's pinned binary oracle on the
same artifact, not with a cross-platform normalized approximation. Add
synthetic DWARF64, truncation, overflow, cyclic-reference and unknown-form
rows before implementing those paths. Optional macro/name indexes, split and
supplementary files, unsupported compression and other architectures get
named refusals until separately covered.

### S1 as implemented

`src/readers/` holds bounded bytes, ELF64, Mach-O 64 with dSYM resolution,
DWARF units, abbreviations, forms, DIE trees, indexed tables, line programs,
DWARF 4 and 5 range and location lists, expressions (decoded, never
evaluated) and CFI. `.debug_frame` and `.eh_frame` are read as separate
formats. `src/dump/` renders the twelve modes, and `src/main.lu` is the
`sniff dump MODE FILE` command. `tools/dump-matrix.py` compares every mode
with its pinned oracle on every built fixture, full bytes and exit status.
`tools/test-hostile.py` runs truncated and corrupted fixtures through every
mode. `tests/evidence/linux/reader-caps.json` records the measured counter
maxima behind each cap.

Stated boundaries that remain:
- The DWARF 5 file-zero ambiguity stays as published; no DWARF 6 rewrite.
- Vendor names appear only when a recorded fixture or a synthetic probe shows them.
- Compact unwind is refused by name (`--unwind-info`).
- Macro and name indexes have no mode yet.
- On hosted CI's macOS job the oracle rows skip by name. No hosted image
  carries the pinned oracle binaries, so those rows are local-record only (README).
- The dump reads one file. Pairing an image with its dSYM by UUID is a reader
  capability (`macho_match_uuid`) that `dump` does not use.

The twelfth mode, `--symbols`, mirrors `readelf --symbols --wide` on ELF and
SDK `llvm-nm --format=darwin --no-sort --debug-syms --no-demangle --no-dyldinfo`
on Mach-O. Both run only as binaries. `sniff-oracle.toml` fixes their argument
vectors, versions and SHA-256 digests. The gate checks the selected binary's
`--version` and bytes before fixture work; a different PATH binary is refused
by name, not silently replaced.

## S2 command/fixture prediction

These are planned command rows, not implemented sniff commands. The current
oracle seed records only the scalar helper stop, arguments, next-line local,
source backtrace and normal continuation under GDB and LLDB.

| Commands | Planned fixture rows |
|---|---|
| run, kill, continue | wolf/scalars, normal exit and a separately owned running inferior |
| break function, file:line, *address; info breakpoints; delete | wolf/scalars and wolf/shared-name, with both module-qualified names and the C main shim accounted for |
| step, next, finish, until | wolf/nested and wolf/loops; exact source-line order |
| bt, frame, up, down | wolf/nested and C/recursion; CFI versus named frame-pointer fallback |
| print, info locals, info args | initialized scalar rows and explicit lupin statement-boundary joins; unsigned boundaries remain a compiler gap |
| x, info registers | C/aggregates and C/pointers; target-width formatting, not host-width inference |

Optimized C inlining and the thread fixture seed later milestones; their
presence in the reader corpus is not S2 command coverage.

## Compiler boundaries

The scalar-types unit has signed `i8` and `int` DIEs for source `u8`, `u64`
and `uint`: the fixture's values 255 and 18446744073709551615 cannot be printed
truthfully using those signed encodings. Correct unsigned type identity and
encoding are needed alongside aggregate types and wolf-owned CFI. The scalar
base-type excerpt and lupin values retain this evidence.

Aggregates, strings, lists, enums and error unions are not described by wolf's
own units. Whole-function fbreg spill locations do not establish declaration
liveness, lexical scopes or live ranges; a variable seen before initialization
is not a verified value. Inline frames and optimized location fidelity remain
separate compiler work. These gaps are recorded, not silently reconstructed
from the source language.

## Evidence boundaries

GDB/LLDB sessions and lupin values are independent binary observations. The
three injected harness failures are wrong-value, wrong-line-order and
missing-frame; source coordinates prevent the C shim from masking frame loss.
A light-slot setup/census observation is not a final heavy-block gauntlet or a
timing measurement. Final-head records and the one-hunk plant are supplied
separately with the PR.

### S2 as implemented

`src/platform/` is the process layer (`linux.lu` for x86-64 Linux, `macos.lu` for arm64 macOS, `arch.lu` for what differs by architecture) and
`src/session/` the debugger: loader, line table, CFI unwinder, DWARF
expression machine, values and formatting, breakpoints, run control,
stepping, and the command interpreter. `src/numfmt/` formats floats exactly.
The platform boundary is the list under "For S3 and S4" in
`notes/sn02-the-linux-core.md`. Boundaries that remain: no CFI from wolf
(frame-pointer fallback), eager DWARF loading, signed encodings for unsigned
wolf types, and the unimplemented commands listed in the note.

### S3 as implemented

`src/platform/macos.lu` starts the child with `posix_spawn` suspended and with ASLR off, takes its task
port with `task_for_pid`, receives its exceptions on a port set with `task_set_exception_ports`, steps with
`MDSCR_EL1.SS` and reads registers and memory through `thread_get_state` and `mach_vm_*`. Breakpoints are
`BRK #0xf000`. `src/session/arm64.lu` unwinds where no DWARF CFI covers a pc: compact unwind from
`__unwind_info`, a prologue and epilogue analysis, and the x29 chain; `maint frames` names the basis per
frame. The dSYM is paired with the image by UUID. The macOS rows are `tests/macos-rows.json`, run by
`tools/session-mac.py`: rows held to sn02's Linux output (after named normalisations and per-line drops
with reasons) and rows held to lldb facts (a named extraction per fact kind). Boundaries that remain: no
symbolication of system images (dyld, the shared cache) until S6, and no `fork` follow mode (a forked
child is detached when it first traps on an inherited breakpoint, after its original instructions are
written back).

### S4 as implemented

PAX answers ptrace(2), wait4(2), `/proc/PID/mem`, `fork` and `execve` with Linux's request numbers, wait
statuses and register layout, so `src/platform/linux.lu` is also the PAX layer and no new platform module
exists. PAX loads only static `ET_EXEC` files, so sniff for PAX is built static (`tools/build-static-sniff.sh`)
and the session runs on static fixtures (`tools/build-session.py --static`). Their gdb goldens are
`tests/evidence/pax-linux`, taken from the pinned gdb on those builds; `tests/pax-rows.json` names the few
per-line drops. `tools/session-pax.py` boots an image under KVM (pelt as init, boreutils' `cat`, the static
sniff, the fixtures and their sources at the paths the line tables name), types one command line at the
console, splits the console by marker, and compares each row with its golden. The five terminal rows are typed
key by key at sniff's own prompt. The same rows also run on Linux (`pax-rows-linux`). Boundaries that remain:
no `/proc/PID/maps`, `auxv` or `task/TID/stat` on PAX, and `personality` answers ENOSYS (`notes/sn04-sniff-on-pax.md`).

### The session's list and help (sniff#11)

`src/session/listing.lu` lists source lines through the reader `step` and `frame` use, in every form of the GDB
manual's "Printing Source Lines" and with gdb's refusals; a frame's printed source line is the one a bare `list`
centres on, and a source file that cannot be read is warned about once, as gdb does. `src/session/help.lu`
answers `help` over `src/session/helptext.lu`, a table generated from the pinned gdb's help output and
restricted to sniff's commands: gdb's names lines, summaries and shared paragraphs, sniff's own paragraphs where
gdb's describe what sniff lacks, and gdb's command names that sniff lacks, which are named as not implemented
yet. At a terminal an empty line repeats the previous one as gdb repeats it. The help rows compare bytes, a
held head, a subset of gdb's lines or sniff's own text, named per row in `tests/session-rows.json`
(`tools/session.py`). Boundaries that remain are listed in `notes/sn06-list-and-help.md`.
