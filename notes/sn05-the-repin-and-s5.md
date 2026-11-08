# sn05: the 0.2.38 re-pin, the startup margin, and S5

Base: sniff trunk `5ceae8e` (sn04 merged as sniff#9). The prediction was committed before code
(`tests/sn05-prediction.json`, `82319fe`). The first PR (sniff#12) was the re-pin and sniff#10; the S5
sections are the second PR's.

## The re-pin: wolf 0.2.38, lupin 0.1.60, every wolf fixture built with `-g`

| pin | version | commit | how it was read |
|---|---|---|---|
| wolf | 0.2.38 | `95ae0827a8ad4d0bbed9302df7811caaa7009fa1` | the tag object and its commit through the API, twice; the archives' sha256 twice after download (`tests/pin-read-1.json`, `-2.json`) |
| lupin | 0.1.60 | `17bd522382373b361fe035a5cc61f9e136e1caba` | the same |
| std | bundled | `d4a4d4cab358e1e8c174f0206f9e13ad5cfe6c61` | the archive's `std/STD-REV`, checked by `tools/fetch-toolchain.py` |

wolf 0.2.38's default tier describes wolf's source types in DWARF, and `-g` adds a non-allocated
`.debug_frame` (its release note, "Source types and call frames in a debugger"). `tools/build-fixtures.py`
and `tools/build-session.py` now pass `-g` for every wolf program: the reader corpus, the session fixtures, the
static PAX builds and the macOS builds.

### Red first

The gate at `dfc3a69` (the pin and `-g`, nothing else) went red at `dump-matrix`, by name: `FAIL dump-debug-info
wolf/{loops,nested,scalars,shared-name,types}/wolf-debug`. A diagnostic run of the same head carried on past the
first red and named every row that moved:

| row | what moved | why |
|---|---|---|
| `dump-matrix`, the five wolf corpus programs | the oracle prints `DW_AT_artificial (0x01)`, sniff printed `(true)` | 0.2.38 describes the runtime's entry shim as a second `main` with `DW_AT_artificial` in `DW_FORM_flag`, a stored byte. No producer in the corpus used `DW_FORM_flag` before; only `DW_FORM_flag_present` prints as `true`. Fixed in `src/dump/info.lu` (`4473aed`) |
| `wolf-types` (gdb goldens, Linux and PAX) | `c`, `narrow`, `$1` read `255 '\377'` for `-1 '\377'`; `d`, `wide`, `$2` read `18446744073709551615` for `-1` | u8, u64 and uint are `DW_ATE_unsigned` now, with their own base-type names: R-sn00-1 is fixed by the producer |
| `wolf-exits-code` (gdb goldens, Linux and PAX) | `code (text=...)` for `code ()`; `info args` prints `text = {data = 0x... "4", len = 1}` for `No arguments.`; the breakpoint is 19 bytes later; `finish` lands on `main () at` without an address | the `str` parameter is now described (a `str` is its runtime header, `data` and `len`) and, as an aggregate binding, spilled where a debugger reads it. The spill moves the first statement, and the return address after the call now starts a line-table row |
| `wolf-recursion` (gdb goldens, Linux and PAX) | `info locals` in the shim's frame: `No locals.` for `No symbol table info available.` | the shim has a DWARF subprogram now (the artificial `main`) |
| `wolf-break-main-two-locations` (sniff only) | sniff put location 1.2 at `<main>`, gdb at `<main+4>` | sniff resolved the shim through its new DIE, which no line-table row covers; such a function now gets the prologue analysis an ELF symbol without DWARF gets, as gdb does (`b08d9ee`) |
| `session-lupin-join`, `wolf/types` | sniff's `255 '\377'` against lupin's `255` | the join reinterpreted signed readings of unsigned values (gap R-sn00-1). With the gap closed, a one-byte integer agrees through its number, and a signed reading is a disagreement (`c6a717e`) |
| `session-unwind-basis`, both wolf rows | every wolf frame is `cfi` | `.debug_frame` covers every wolf function and the shim; until 0.2.37 they used the frame-pointer fallback. The row was written to go red the day this happened (`6746e46`) |

The gdb goldens that moved were re-captured from the pinned gdb in the oracle image (`916a262`), never edited:
`tests/evidence/linux-s2` and `tests/evidence/pax-linux`, three rows each. The other 14 wolf rows and all 124 C
rows held, and `session-oracle-stable` is green at the head.

### What did not move

- The S0 baselines (`tests/evidence/{linux,macos}/`, `linux-session/`, `macos-session/`) stay as bound at S0; their
  provenance names the commits and toolchain they were captured with. The live gate re-derives the census, the
  lupin values and the transcript on every run against the pinned toolchain. The lupin values are unchanged
  but for the version line, and the scalars transcript states the same facts.
- `tests/evidence/linux/reader-caps.json` is re-measured (`36cfa9d`): the DIE counts move by under 0.2%, and the
  charged tree work halves, because a reference check now costs one unit (below). Every cap holds, the
  narrowest at 2.67 times the measured maximum.

### A run-time address at PAX's console: the heap normalisation

The first gauntlet of the cuts' head (`666ff8f`) was red at one row of PAX's console, `wolf-exits-code`:
`text = {data = 0x525650 "4", len = 1}`, where the golden (the pinned gdb on Linux, the same static build) reads
`data = 0x525b60`. `text` is a `str` parameter, described since 0.2.38, and its data is the program's
argument, which the runtime copies to the heap at start.

Both addresses are in the program's break. The static build's last loaded byte is `0x5230cf` (`_end` is
`0x5230d0`). PAX's `kernel/vm` starts the break at the page above, `0x524000` (its `start`), and states that
Linux does the same plus a random offset, which both debuggers turn off. The two addresses differ by what the
runtime allocated there before it copied the argument, which follows what the program was given at start
(its arguments and environment); gdb's inferior on Linux and sniff's at PAX's console are not given the same.
On Linux, sniff's run of the same build reads `0x525b60`, as gdb's does (`pax-rows-linux`, the same record).

So the PAX set now normalises by name a hex address inside the program's break, from the page above its last
loaded byte up to the 64 MiB that PAX's break may not pass, to `<HEAP>` (`e4b3259`, `7450274`). The rest of the
line is still held: `"4"` and `len = 1`. Every golden was re-captured from the pinned gdb with it, and only
that line of `tests/evidence/pax-linux/wolf-exits-code.out` changed (`099983f`); the S2 set's 141 goldens are
stable.

The same rows on Linux (`pax-rows-linux`) passed with the raw address, since gdb and sniff run the program
on one kernel with one environment and get one heap; they now read `<HEAP>` too. The S2 set (dynamic builds,
Linux only) still holds heap addresses exactly (`0x5555555b2300` in the same row), for the same reason, and no
second kernel shares its goldens.

## sniff#10: the startup margin

### Where the time went

Measured before code: sniff built by 0.2.37 and 0.2.38, `break helper` alone (load and resolve, no process),
on the large-DWARF fixture. It is a 14.3 MB wolf program whose DWARF is the linked runtime's Rust units: 190
units, 553,175 entries, 1,429,912 attributes, 129,077 line rows. CPU is from the child's rusage (the minimum of
nine). The attribution is callgrind's instruction count, which neighbours on a shared host cannot disturb.

| part of startup | share of instructions |
|---|---|
| reading every DIE (`dwarf_info_read`) | 56% |
| … of which checking each reference by binary search | 15% |
| the subprogram scan (`p.info.entries[e]` through the mutable `Prog`, about 1,190 instructions an entry) | 15.5% |
| sorting the line rows (the standard merge sort) | 11.6% |
| decoding the line programs | 10.3% |

Instruction counts were half the story. CPU time was 0.31 s user and 0.24 s system: the system half is page
faults, 181,000 of them, for a 698 MB peak. A page-level memory profile (valgrind's massif) showed where the
memory went. The DIE lists grew by doubling and held about twice their size, the DIE tree was copied once
into `Prog`, and the standard sort's seventeen passes each built a fresh list (139 MB).

### The cuts

Each cut is its own commit. Each row is the same measurement, `break helper` on the large-DWARF fixture, one
job per series on one light slot; the two series share a reference row (cut 4).

| commit | cut | CPU (min of 9) | user | system | peak RSS | instructions |
|---|---|---|---|---|---|---|
| `5ceae8e` | the base, built by 0.2.38 | 0.546 s | 0.310 | 0.236 | 698 MB | 4.47 G |
| `641fe23` | the subprogram scan over a read-only view | 0.540 s | 0.286 | 0.253 | 699 MB | 3.87 G |
| `a705031` | the DIE tree moved into `Prog`, not copied | 0.504 s | 0.290 | 0.214 | 573 MB | 3.86 G |
| `da77ebd` | references checked against a bitset of entry starts | 0.455 s | 0.221 | 0.235 | 574 MB | 3.29 G |
| `3ccb699` | the line sort by runs laid end to end (it fell back to the full sort here) | 0.423 s | 0.242 | 0.181 | 582 MB | 3.32 G |
| `f107d1e` | fast paths in the byte primitives | 0.422 s / 0.388 s | 0.231 | 0.190 / 0.156 | 582 MB | 2.89 G |
| `e02bede` | the DIE lists reserved from the section's size | 0.328 s | 0.184 | 0.145 | 382 MB | 2.87 G |
| `d32816f` | the line sort as a natural merge over an index list | 0.225 s | 0.164 | 0.061 | 202 MB | 2.55 G |
| `666ff8f` | the line-row lists reserved from the programs' lengths | 0.220 s | 0.161 | 0.060 | 186 MB | 2.54 G |

`e083ee1` tried to move the file bytes too and did not compile (a `take` parameter's region cannot be stored
into `p`, E1004); `a705031` keeps that copy.

From 0.546 s to 0.220 s is a 60% cut. None of it changes what is read or printed:

- `dump-matrix`, `hostile-inputs` and the reader rows hold byte for byte.
- A malformed reference is still refused by name at load (`src/info_test.lu`).
- The line sort is held against an insertion sort, for runs laid end to end and for interleaved ones
  (`src/sort_test.lu`, native and checked).

The order (addr, ord) is total, so the sorted list is unique and any correct sort gives it.

### The margin, derived

R-sn05-1 was ruled (A): cut the cost, then derive the margin from the measured spread. The rule:

    margin = ceil_to_0.5(local ratio after the cut x 1.43 x 1.25)

- **1.43** is the worst hosted-to-local factor seen. Five hosted runs at the old code read 4.80, 5.36, 5.83, 6.06
  and 6.02, against the local record 4.25 of the same code (sniff#10, nightly run 42367656134).
- **1.25** is headroom for a runner type not yet seen.

| head | local ratio (the gate's `perf startup-wolf-large-dwarf`, a locked block) |
|---|---|
| `dfc3a69` (no cut) | 4.75 (oracle 0.118 s, sniff 0.558 s) |
| `36cfa9d` (the first four cuts) | 3.47 (0.136 s, 0.472 s) |
| `666ff8f` (every cut) | 1.90 (0.117 s, 0.221 s) |

1.90 x 1.43 x 1.25 is 3.40, so the margin is 3.5 (`3ca6c8a`). The base code's 4.75 is red against it, and the
head is green. At the worst factor seen, a hosted run of the head would read 2.72. The PR's hosted run is the
check on the factor: sniff#12's labelled run (42462212567) read 2.53, a factor of 1.30 over the
local 1.94 of the same head. The macOS row keeps its stated margin (6.0 against lldb, measured 0.13); hosted macOS CI
skips it by name.

## S5: watchpoints and expressions

S5 is the contract's two items, watchpoints and `print` over expressions, then the evaluator's thin extras:
conditional breakpoints, `display`, and wolf aggregates. Every C row is held to the pinned gdb's transcript on
Linux (`tests/evidence/linux-s2`, both compilers), on the PAX set's static builds (`tests/evidence/pax-linux`)
for every row but the watch rows, and to the same transcript on macOS with each arm64 difference named. Wolf expressions are held to lupin's
values and to the wolf spec's expression rules.

### Watchpoints

`watch`, `rwatch` and `awatch` set a hardware watchpoint on the place an expression names. A place is 1, 2, 4
or 8 bytes, aligned to its size. sniff has no software watchpoints, and it says so by name when a place
cannot go in a slot. The C fixture is `fixtures/session/c/watch/main.c`: a global counter, a struct with an
array member, a pointer to it, and a loop whose local is watched until its frame returns. The wolf row watches
`total` in `fixtures/wolf/loops`.

- **Linux x86-64.** DR0-DR3 hold the addresses. DR7 has per slot i the local enable bit 2i, R/W at bits 16+4i
  (01 data writes, 11 data reads or writes) and LEN at bits 18+4i (00 one byte, 01 two, 11 four, 10 eight). The
  registers are written through `PTRACE_POKEUSER` at `offsetof(struct user, u_debugreg)` (848, slots of 8 bytes,
  probed from the system headers by `tools/abi-probe.c` and held by `abi-constants`). DR7 is cleared first, so
  no half-written slot can fire. At a SIGTRAP stop, DR6's B0-B3 name the slot that fired, and DR6 is then
  cleared, since the processor never clears it (Intel SDM vol. 3, 18.2).
- **macOS arm64.** The thread's `ARM_DEBUG_STATE64` (flavor 15) holds the watch value and control registers.
  Each control word has E, PAC = 2 (EL0), LSC (2 store, 3 load or store) and the byte-address select for the
  watched bytes. `hw.optional.watchpoint` gives the slot count (4 on both Macs used). A watch trap is
  `EXC_BREAKPOINT` with code `EXC_ARM_DA_DEBUG` (0x102) and the data address in the subcode. It is taken before
  the access completes, so sniff clears the slots, steps the thread over the access, and sets the slots again
  before it reports.
- **macOS 15 kept a step armed.** On a second Mac (macOS 15.5), a watch row's script failed in 40 of 140 runs: after
  the breakpoint's step-over, every resume trapped at once at the same pc. The exception state named a
  software step taken with no instruction run (ESR class 0x32, ISV 0): the step was still armed in the
  hardware, though the thread's debug state read back with the bit clear. Runs with no watch armed never
  failed (0 of 110), and macOS 26.4.1 never failed (0 of 30). sniff now writes an empty debug state before the
  one that clears the step bit, so the kernel drops the thread's state and loads the next one afresh
  (`3ff1b50`). After it: 0 of 60 on macOS 15.5 and 0 of 30 on macOS 26.4.1.
- **gdb's semantics, from its transcripts.** `watch` reports `Old value` and `New value` only when the value
  changed; a write of the same value is passed silently. `rwatch` reports `Value =`. x86 has no read-only data
  breakpoint, so a read slot fires on writes too: an `rwatch` whose value changed was a write and is passed, and
  a write of the same value is reported as a read, as gdb reports it. `awatch` reports Old and New when the value
  changed, and `Value =` when it did not. A watch on a local is deleted when its frame returns, with gdb's two
  lines (`Watchpoint N deleted because the program has left the block in` / `which its expression is valid.`).
  `info watchpoints`, `delete` and the hit counts in `info breakpoints` are gdb's.

| row (gcc and clang) | holds |
|---|---|
| `watch-*-global` | a global's writes: changed values reported, a same-value write passed |
| `watch-*-local-scope` | a loop local watched until its frame returns, then deleted with gdb's text |
| `watch-*-members` | `origin.hist[2]` and `cursor->y` (through a pointer) at once; `info watchpoints` |
| `watch-*-delete` | `info breakpoints` lists the watchpoint; `delete 2`; the program runs to its end |
| `rwatch-*-global` | reads reported, a changed write passed |
| `awatch-*-global` | reads and writes, each in its own form |
| `watch-wolf-local` | a wolf local's changes, then the watch deleted when `sum` returns |

`session-expr-join` also holds the wolf watch to lupin: the New values sniff reports for `total`, set once it
is initialised, are the values lupin's trace gives it afterwards, each change once (`1, 3, 6`).

On macOS, two clang rows drop lines by name, both for where arm64 clang's line table puts the stop after a
write (the SDK clang, `-O0`):

- `watch-clang-local-scope`: in `walk`, line 29's store to `total` (`str w8, [sp, #0x8]`) is followed by a row
  for line 30, the loop body's closing brace (`b`), so the stop after the write is at line 30. On x86-64 it is at
  line 28, the loop's increment.
- `watch-clang-members`: line 37's store to `cursor->y` (`str w8, [x9, #0x4]`) is followed by `adrp x9`, line
  38's address computation, still inside line 37's row. So the stop after the write is mid-line 37, where
  x86-64's is at line 38's start.

### Expressions

`print` takes an expression, not just a name. The parser is sniff's own (`src/session/eval.lu`). A frame
whose unit's `DW_AT_producer` starts with `wolf` is read in wolf mode; any other is read in C mode.

- **Both modes:** names (the frame's locals and parameters, then globals), value history (`$`, `$N`) and
  registers (`$pc`), field access, indexing, unary
  `-` and `!`, the binary arithmetic, bitwise and shift operators, comparisons, `&&` and `||`, and parentheses.
- **C mode** (held to gdb): `->`, unary `*`, `&` and `~`, casts to the frame's types and C's base types, C's
  integer promotions and usual arithmetic conversions, pointer arithmetic, and gdb's errors by their text
  (`There is no member named nosuch.`, ``cannot subscript something of type `int'``, `Division by zero`). An
  address in data prints its symbol, as gdb's does (`(int *) 0x555555558014 <origin+4>`).
- **wolf mode** (held to the wolf spec): `as` casts, integer literals taking the other operand's type, `!` on an
  integer as the bitwise not, comparisons that do not chain, booleans printed as `true` and `false`. A member
  of a reference is read through it, and a `List[T]` is indexed through its header (`data`, `len`), checked
  against its length as the language checks it.
- **References.** A wolf `mut` parameter is described as a reference (`DW_TAG_reference_type`). sniff prints it
  as gdb prints one, `(struct Point &) @0x7fffffffeb40: {x = 4, y = 2, hist = 0x5555555b02d0}`, and reads
  through it wherever its value is used (`wolf-mut-reference`).
- **clang's DWARF 5 globals.** clang on Linux locates a global by `DW_OP_addrx`, an index into the unit's
  `.debug_addr` contribution, where gcc writes `DW_OP_addr`. sniff resolves both.

`session-expr-join` holds wolf expressions to lupin's place trace. At the stop in `bump`, each place lupin
names (`p.x`, `p.y`, `p.hist[2]`, `by`) is a wolf expression, and sniff must print lupin's value for it. Five
derived expressions over those places (`p.x + by`, `p.hist[2] * 2 - p.y`, `(p.x + p.y) % by`, `p.x == 4`,
`p.hist[2] > by && p.y < 10`) must print the values the spec's rules give. All nine agree, on Linux and on
macOS.

### Conditions and display

- `break LOCATION if EXPR` and `condition N EXPR`: the hit counts only when the condition is true, as gdb
  counts it, and `info breakpoints` prints `stop only if EXPR` (`break-*-condition`,
  `break-*-condition-command`).
- `display EXPR` and `display/FMT EXPR` print at every stop, `next` included, numbered as gdb numbers them.
  `undisplay` and `info display` are gdb's. In batch mode gdb does not print a new display at once, and neither
  does sniff (`display-*-stops`).

### wolf 0.2.38 places a struct local where it is not

At the stop before `count = count + p.hist[2]`, main's `var p = Point {...}` has a `DW_AT_location` of
`DW_OP_fbreg -192`. On macOS arm64
that is the frame's lowest address (sp), while the code builds the struct at `sp + 0x60` (`x23` in the
disassembly) and passes that address to `bump`. On Linux x86-64 the slot at the stated offset holds a stack
pointer and small integers. The pinned gdb on Linux, lldb on macOS and sniff on both read the same wrong bytes
there (`p = {x = 8, y = 140737488350048, hist = 0x1}` on Linux). `count`, a scalar local of the same frame,
reads right. The parameter of `bump`, a reference to the same struct, reads right on both. So the expression
join stops in `bump`. The producer's location is wolf-lang#1078.

### The PAX half, drafted for a px lane

The watch rows are skipped by name in `tests/pax-rows.json`. PAX's ptrace has no debug-register path yet. The
lane that adds it needs:

1. `PTRACE_PEEKUSER` and `PTRACE_POKEUSER` at `offsetof(struct user, u_debugreg)` (848, 8-byte slots): DR0-DR3,
   DR6 and DR7. An address must be a user address, aligned to its length. DR7 may set only the local enable
   bits, R/W 01 or 11 and the LEN values: no R/W 10 (I/O), no general-detect bit. Any other value is refused
   with `EINVAL`, never loaded.
2. DR0-DR3 and DR7 saved and restored per task at each switch, and cleared at `execve`. A traced task's slots
   must never fire in another task.
3. `#DB` from a data breakpoint delivered to the task as SIGTRAP with `si_code` TRAP_HWBKPT. DR6 stays readable
   through PEEKUSER until the tracer clears it.
4. The procfs gaps sn04 witnessed that these rows touch: `/proc/PID/maps` and `auxv`.
5. Then the watch rows (six per compiler, and the wolf row) run at PAX's console under KVM, as the other rows
   do, held to goldens the pinned gdb gives the static builds on Linux. These goldens are not captured yet,
   since the PAX set skips the rows by name.

### S5's remainder

Listed per R-sn05-2, none of it started:

- software watchpoints (a place that is not 1, 2, 4 or 8 aligned bytes, or more places than slots), `watch -l`,
  conditions on watchpoints, and watchpoints on registers
- lldb-fact rows for watchpoints on macOS (`watchpoint set variable`): the gdb transcripts run on the Mac with
  named drops hold the watch text there
- calling the program's functions from an expression, `sizeof`, string and character comparisons, and
  assignment (`print x = 3`, `set var`)
- wolf mode's enums, error unions and `?`, slices, tuples beyond `.0` member access, and `<=>`
- `display` of memory and instructions (`display/4xw &v`, `display/i $pc`); a display takes `print`'s value
  formats only (`x d u o t c a`)
- the PAX debug-register path above

## R-list

- R-sn05-1 (ruled A): the cuts above, then the margin by the rule above.
- R-sn05-2 (ruled (b)): S5 is the contract's two items first (watchpoints; `print` with field access,
  indexing and arithmetic), then the evaluator's thin extras (conditional breakpoints, `display`, wolf
  aggregates). Whatever does not fit is listed as S5's remainder.
- R-sn05-3 (ruled): sniff's own expression parser for the subset a debugger needs, in a wolf mode and a C mode
  chosen by the unit's `DW_AT_producer`. It is held to gdb or lldb on C, and to the wolf spec's expression
  grammar on wolf. fenrir's front end is not vendored.
- R-sn05-4 (accepted): the S0 baselines stay as bound at S0. Re-binding them needs S0's
  normalisation procedure, and the live gate already re-derives what they record.

## Forbidden

The clean room held. These were read: the DWARF 5 standard, wolf-lang's 0.2.38 release note and its spec's
memory-model chapter, as the producer's and the language's documentation, and valgrind's manual. The pinned gdb
and llvm-dwarfdump ran only as binaries in the oracle image, and lldb only as the system binary. No debugger's,
DWARF library's or Linux's source was read. Of PAX, this organisation's own kernel, `kernel/vm`'s statement of
where a program's break starts was read for the heap normalisation. For S5: the Intel SDM (vol. 3, chapter 18,
the debug registers), the Arm ARM's self-hosted debug chapter (the watchpoint registers, MDSCR_EL1 and the ESR
classes), ptrace(2) and sigaction(2), the GDB manual, the macOS SDK headers' declarations (`mach/arm/_structs.h`,
`mach/arm/exception.h`, `mach/thread_status.h`) and the wolf spec's expression and type chapters. lupin ran only
as a binary.

## Done-when

- [x] the prediction before code
- [x] the 0.2.38 re-pin, fixtures with `-g`, red first, every moved golden re-captured and explained
- [x] #10: where startup goes, measured; the cuts, each measured; the margin derived
- [x] the first PR's gauntlet, plant and macOS records (sniff#12)
- [x] S5: watchpoints on Linux and macOS held to gdb's transcripts; expressions in a C mode held to gdb and a
  wolf mode held to lupin and the spec; conditions and `display`; the PAX half drafted
- [ ] S5's gauntlet, plant and macOS records: in the second PR
