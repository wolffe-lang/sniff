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

PAX's ptrace answers the debug-register requests a watchpoint makes (POKEUSER of DR0-DR3 and DR7, PEEKUSER and
POKEUSER of DR6) as Linux does, so the watch rows run at PAX's console as well. `tests/pax-probe/dr.c` makes exactly
those calls; its Linux answer is a golden (`tests/evidence/pax-linux/probe-dr.out`), and the console run holds PAX's
answer to it. A row of the PAX set that is skipped for a gap in PAX names the probe that witnesses the gap (`gap` in
`tests/pax-rows.json`); while PAX answers that probe differently from Linux the row is SKIP with the first differing
line, and once PAX answers alike the row is red by name (`skip-stale`) until its skip is removed. A skip for the
harness's own limit says `harness`. `tools/session-pax.py --smp N` (and `PAX_SMP` for `tools/gate-pax`) gives the guest
more than one processor.

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

### The session's threads and signals (S6)

`src/session/threads.lu` keeps the program's threads all-stop: on Linux and PAX a new thread is traced from its
clone event (`PTRACE_O_TRACECLONE`) and a stop stops every other thread (a SIGSTOP to each by `tgkill(2)`, each
awaited); on macOS the task is suspended at each reported exception and its thread list read then
(`task_threads`). It prints gdb's thread lines, `info threads` and `thread N`, in gdb's three target-id forms on
Linux and PAX and in sniff's own on macOS. `src/session/signals.lu` answers `handle`, `info signals` and `signal`
over gdb's signal table (`src/session/sigtable.lu`, generated from the pinned gdb's `info signals`), with pass
read at the resume. `src/session/libs.lu` unwinds a frame in a shared library by the library's own `.eh_frame` and
names it from the library's symbols. The macOS thread rows are lldb fact rows; the PAX rows run at PAX's console,
where a thread's name is the program's base name until PAX keeps procfs `comm` (pax#322). Boundaries that remain
are listed in `notes/sn07-threads-and-signals.md`.

`src/session/attach.lu` answers `attach PID`, `detach` and `sniff -p PID`: on Linux and PAX by `PTRACE_ATTACH` of
every thread in `/proc/PID/task` and `PTRACE_DETACH` of each, on macOS by the task port, sniff's exception port and
`PT_ATTACHEXC`, with the detach and kill orders a probe measured. A refused attach prints the errno the kernel
gave, after gdb's already-traced warning when another tracer holds the process. A session that ends attached
detaches. The attach rows start the sleeper fixture as the harness's own child and start the debugger once it
blocks; the macOS rows are lldb fact rows, and the PAX rows run at PAX's console. Boundaries that remain are listed
in `notes/sn07-attach-and-detach.md`.

### Core files (S7, Linux)

`src/readers/core.lu` reads an ELF64 x86-64 core: its PT_LOAD segments and the notes of its PT_NOTEs, as spans into
the file, every read bounded and charged. Notes are laid at 8 when the PT_NOTE's p_align says 8 and at 4 otherwise
(gdb's gcore writes p_align 1 and pads at 4); any other alignment is refused by name. The descriptors are decoded
only when a caller asks: threads (NT_PRSTATUS), the process (NT_PRPSINFO), the auxiliary vector and the mapped
files (NT_FILE), at the offsets `tools/abi-probe.c` measures against the C library. `sniff dump --notes` lists a
core's notes as the pinned readelf does. `src/session/core.lu` reads a core as a stopped program, given as
`PROG CORE`, `-c CORE [PROG]` or `core-file CORE`: every memory, register and thread-pointer read goes through
`src/session/source.lu`, which answers from the core when there is one. Memory is a PT_LOAD's bytes, else the bytes
of the file NT_FILE maps there (gcore leaves a library's unmodified text out of the core), else unreadable. A
position-independent program is placed only when its build ID is the core's (no symbol of it is shown otherwise),
where a program loaded at its own addresses keeps its symbols, as gdb does. `info proc mappings` lists NT_FILE
over a core, which the pinned readelf declines to decode. The rows take every core afresh with the
pinned gdb's `gcore` and hold sniff to gdb's session over the same core, on the Linux set and, for the static
builds' cores, at PAX's console.

### Core files (S7, macOS)

`src/readers/macho_core.lu` reads an arm64 MH_CORE as lldb's `process save-core` writes it: its LC_SEGMENT_64
segments, one LC_THREAD a thread with its flavours walked by their counts (ARM_THREAD_STATE64, ARM_EXCEPTION_STATE64),
and its LC_NOTEs. The layouts are the SDK's declarations, held by `tools/abi-probe-macos.c`. Two notes have no
declaration and were derived from lldb's own cores against lldb's `image list` (tests/s7-macho-prediction.json):
`all image infos`, the images with their paths, UUIDs, load addresses and segments, the program first; and
`addrable bits`. Every cap (load commands, segments, threads, flavours, a flavour's words, notes, images, a path's
bytes, an image's segments, the work) is the caller's, and a reader unit row holds each at its value and one past it.
`src/session/core.lu` reads such a core as a stopped program with the forms an ELF core has. Its segments are its
memory, and the program's own sections the memory it leaves out. The program is the image list's first image: one
given whose UUID differs is not placed, and with none placed the file the core names is read. The thread that
stopped is the one whose exception class is a stop (a breakpoint is SIGTRAP, a data abort SIGSEGV). The system
libraries' text is in the dyld shared cache, neither in the core nor in a file, so their frames have no name, as live.
The rows take every core afresh with the pinned lldb, under the take's own directory, capped at 64 MiB and deleted at
the end of the take; they hold sniff, over the take's own core, to the facts lldb gave over the capture's core of the
same stop. A stack word is compared as its distance from its frame, because a core's stack sits where the lldb that
wrote it put it: the gate's lldb is `/usr/bin/lldb` on every Mac (the harness's own PATH), a shim whose four added
variables move the stack 352 bytes from where the evidence's `xcrun --find lldb` put it. The return address the
memory row reads is compared as it is: lldb starts the program without address randomisation. The refusals of run control are held by
the Linux set's `core-gcc-refuse-*` rows, run over a Mach-O core of the clang build of the same program; anything
macOS-specific in how a refusal is reached is held by the macOS `expect` rows. Hosted macOS skips these rows by name
(they need the pinned lldb to write their cores): the Mac's record is their only evidence.

### Remote targets (S8, PR 1)

`src/remote/` is the client side of the GDB remote protocol, from the GDB manual's nodes alone (docs/SOURCES.md).
`packet.lu` frames and decodes packets (the checksum, acknowledgments and no-ack mode, the `}` escape, `*`
run-length decoding, hex, the standard replies), each cap the caller's: a packet's size, a reply's, resends and a
reply's time, each held by a unit row at its value and one past it. `tdesc.lu` reads a target description: the XML
subset a register file needs, inclusions resolved in place, register numbering and the `g` layout, and refuses one that
lacks `org.gnu.gdb.i386.core`'s registers. `link.lu` is one TCP connection (std.net) holding the socket's descriptor,
so a session can read a stopped target through a borrowed value; it reads a byte at a time and scans a packet once it
is whole. `client.lu` is the connect sequence (qSupported, the description, the threads), registers by `g`, memory by
`m`, software breakpoints by `Z0` (decided by the stub's reply alone), hardware breakpoints and watchpoints by `Z1` to
`Z4`, resumption by vCont (or `c` and `s`), stop replies with console output, the interrupt byte, a thread's extra
information, and `D`, `k` and closing the connection. A stand-in stub over the loopback drives the unit rows.

`src/session/remote_target.lu` makes a remote target the session's third source of a stopped program's memory and
registers (`src/session/source.lu`), beside a process and a core: `target remote HOST:PORT` (`:PORT`, `tcp:`), with
the pinned gdb's refusals, `disconnect`, `detach`, `kill`, `info threads`, breakpoints, `hbreak` (a remote target's
`Z1`; on a process or a core sniff refuses it by name), stepping, `finish`, the interrupt (a terminal's SIGINT sent on
as 0x03) and watchpoints. The register slots are Linux's x86-64 `user_regs_struct`, filled by name from the
description. The kernel rows (`tests/remote-rows.json`, `tools/session-remote.py`) boot PAX's console image under
QEMU's gdbstub at one processor, the processor frozen at reset, and hold sniff's terminal transcript to the pinned
gdb's: a golden is written only when a second capture on its own boot holds it, and each normalisation is declared
per row and replaces a value in a line that must be there. The rows run under KVM and TCG on the record host
(`tools/gate-remote`); a host with no kernel image skips them by name with the count held (`tools/gate`), as does the
Mac, whose build has no x86-64 register, CFI or call tables for the kernel. Boundaries that remain: no assignment
(`set var`) to memory or registers, no `<flags>` types in `info registers` (three rows wait for these as named
skips), and no Mac build for the kernel rows.

Every load base comes off an address through `file_address` (a census in `tests/test_session.py` holds that no other
code subtracts one): an address or pc below a moved program (`x/2xg 0`, a call through a null function pointer) finds
nothing instead of trapping, and a frame at a pc in no known code takes its caller from the top of the stack.
