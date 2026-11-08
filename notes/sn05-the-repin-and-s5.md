# sn05: the 0.2.38 re-pin, the startup margin, and S5

Base: sniff trunk `5ceae8e` (sn04 merged as sniff#9). The prediction was committed before code
(`tests/sn05-prediction.json`, `82319fe`). This note covers the first PR (the re-pin and sniff#10); S5's
sections follow with the second PR.

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
check on the factor. The macOS row keeps its stated margin (6.0 against lldb, measured 0.13); hosted macOS CI
skips it by name.

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
where a program's break starts was read for the heap normalisation.

## Done-when

- [x] the prediction before code
- [x] the 0.2.38 re-pin, fixtures with `-g`, red first, every moved golden re-captured and explained
- [x] #10: where startup goes, measured; the cuts, each measured; the margin derived
- [ ] the gauntlet, the plant and the macOS records: in the PR
