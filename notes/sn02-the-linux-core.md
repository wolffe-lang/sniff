# sn02: the core on Linux x86-64 (S2)

`sniff -batch -x SCRIPT PROG` (and `sniff PROG` in a terminal) starts PROG as
its own child under `ptrace(2)` and debugs it with gdb's command language:
`run`, `kill`, `continue`, `break`/`tbreak` (function, `file:line`,
`*address`), `delete`, `ignore`, `info breakpoints`, `step`, `next`, `until`,
`stepi`, `nexti`, `finish`, `bt`, `frame`, `up`, `down`, `print`, `output`,
`x`, `info locals`, `info args`, `info registers`, `echo`. 141 session rows
(five of them in a pseudo-terminal) are held to transcripts of the pinned
gdb 15.1; wolf locals are held to lupin's values.

## Prediction

`tests/sn02-prediction.json` was committed before any code. Scored:

- **State machine and requests.** As predicted: not started, stopped,
  exited, killed or signalled; `TRACEME`, `CONT`, `SINGLESTEP`, `PEEK`/`POKE`,
  `GETREGS`/`SETREGS`, `SETOPTIONS`. Added by the work: `GETFPREGS` (xmm0 for
  `finish`), `GETEVENTMSG` and `DETACH` (a forked child is detached with its
  breakpoints removed; S2 follows the parent only and prints gdb's
  `[Detaching after fork ...]` line, which says so).
- **Wrong in the prediction.** It said a `SIGTRAP` the program raises itself
  is delivered to its handler. gdb treats `SIGTRAP` (and `SIGINT`) as nopass:
  the program stops with "Program received signal SIGTRAP", and `continue`
  does not run the handler. sniff follows the recorded transcript
  (`odd-*-signals`).
- **Not predicted, found by the transcripts.**
  - gdb prints an exit code as `%#o` (`0377`).
  - A literal `break *ADDR` is absolute and is not relocated by the load base; a
    symbol is.
  - gdb records a line-table row of an unchanged line only when that line never
    had a discriminator, and shows a frame address when the pc is not at an
    `is_stmt` row start (gcc's loop condition, wolf's first non-statement row).
  - `step` and `next` differ on a return into code with no line info: `next`
    stops there, `step` runs on.
  - The pending-breakpoint errors (`Function "x" not defined.`) do not abort a
    `-x` script, but most other errors do.
  - gdb adds `LINES`, `COLUMNS` and `PWD` to the program's environment; sniff
    does the same, so stack addresses (`argv=0x7fffffffed28`) match unnormalised.
- **R-sn02-1..3** held as ruled. `Run till exit`, `Starting program:` and
  `Continuing.` are produced in terminal mode only; the terminal rows normalise
  the prompt, carriage returns and the 80-column wrap, each by name
  (`tty`, `wrap80`). The ABI numbers come from `tools/abi-probe.c`.
- **Red first.** The prediction, the rows and their goldens were committed
  before the code that turns them green, chunk by chunk; each chunk's red
  record is in the PR.

## Forbidden

Read: the man pages listed in `docs/SOURCES.md` (ptrace, wait, signal, proc,
personality, execve), DWARF 5 and the psABI as before, and the GDB manual for
command names. Not read: any debugger, DWARF library, libc or kernel source,
or any header text. The pinned gdb and lupin ran only as binaries in the oracle
container; every gdb transcript is a recording of that binary. Processes
started: only the lane's own fixtures, as sniff's children; nothing attached.
The container needed `--cap-add SYS_PTRACE` and `seccomp=unconfined` (the
default profile refuses `personality(ADDR_NO_RANDOMIZE)`); no host setting was
changed.

## Inputs verified

- **Constants.** `tools/check-abi.py` compares `src/platform/types.lu` with the
  probe's output; the probe is re-run and diffed in the Linux gate. The probe
  clears the core-dump bit of a status, which depends on the host.
- **Man pages against the probe.** ptrace(2) asks for word-aligned offsets only for
  the USER area; `POKEDATA` at an unaligned text address worked in every run
  (breakpoint bytes).
- **Goldens.** `session.py oracle` re-runs gdb live and compares it with the
  stored goldens, so a drifted oracle is red rather than silently accepted.
- **Exact floats.** `%.9g`/`%.17g` are produced by exact decimal expansion
  (`src/numfmt`, 13 unit rows, native and checked).

## Evidence index

| Row | Witness |
|---|---|
| session rows (batch) | `tools/session.py check`: 136 rows, gdb goldens in `tests/evidence/linux-s2/` |
| session rows (terminal) | the same, 5 rows through a pty |
| harness without a debugger | `tests/test_session.py` (normalisers, inventory, a replay sniff, red on a changed output or missing golden) |
| ABI | `tools/check-abi.py` and `tests/evidence/linux-s2/abi.txt` |
| wolf values against lupin | `tools/session-values.py`: scalars, nested, loops, types |
| which frames use CFI | `tools/session-unwind.py` |
| timed rows | `tools/session-perf.py`, below |
| platform and formatting units | `src/platform_test.lu`, `src/fmt_test.lu`; live `src/live_platform.lu` |

**Wolf frames use the fallback.** `maint frames` (sniff's own command, not
gdb's) names the basis of each frame. gcc and clang frames unwind through
`.eh_frame`. wolf 0.2.37 emits no CFI for its own functions, and the linked
runtime's `main` shim has none either (S0 expected one): every unwound wolf
frame uses the frame-pointer fallback, with gdb's prologue and `ret` cases.
The rows that rest on it are `wolf-*` and `tty-wolf-recursion`; the unwind
row goes red by name when s283 lands.

**Timed rows** (child CPU, minimum of nine interleaved runs, ratio sniff/gdb):
startup to first breakpoint on a C program 0.03 (margin 1.0); a 10,000-hit
loop 0.32 (margin 2.0); startup on a wolf binary 4.2 to 4.8 (margin 6.0).
The last is a finding: sniff reads every unit eagerly through the S1 reader
(about 0.3 s of 0.5 s is the linked runtime's Rust DWARF), gdb reads lazily.

**Stated boundaries.**

- The `/usr/lib/` to `/lib/` rewrite of a shared-library path (the maps show the
  real path, gdb shows the one the loader recorded) is a substitution, not a
  measurement.
- libc frames are `?? () from LIB` with no symbols; `bt` stops at `main`.
- Not implemented: conditional breakpoints, `info frame`, `list`, `info line`,
  `x/i`, `starti`, `advance`, watchpoints, attach, threads.
- The libc-path and `maint` items above; `x`, `print` and `info registers` cover
  base types, pointers, arrays, structs and enums that the DWARF describes.
  wolf describes only scalars today; an aggregate is refused by name
  (`<unsupported type>`), never rebuilt from source.
- Unsigned wolf types are signed in the DWARF (R-sn00-1); sniff prints what the
  DWARF says and the lupin join counts the reinterpretation under that gap.

## For S3 and S4

The session talks to the platform only through `src/platform`: spawn a child
stopped at exec (and report the load base); wait and decode a status; resume
or single-step with a signal; read and write memory; read and write the
register file; read the return-value floating register; kill; report and
detach a forked child; name the shared library at an address. x86-64
specifics that sit above it and must be parametrised: the `int3` byte,
call detection after a step, the prologue analysis, the DWARF register map,
the red zone and the return-value registers.

- **sn03 first items (macOS arm64).** (1) the same rows run against lldb
  transcripts, red first; (2) a platform layer over task and exception ports:
  spawn suspended, `BRK #0` insertion, single-step, register state, memory
  read/write; (3) Mach-O plus dSYM loading into `Prog` through
  `macho_match_uuid`; (4) compact unwind (R-sn00-2) for `bt`; (5) ad-hoc signed
  test targets.
- **sn04 first items (PAX).** (1) wait for px102's `ptrace`; (2) a platform
  layer over PAX's requests with the same primitives; (3) static sniff on the
  dev image; (4) the same rows typed at the console, compared with the Linux
  goldens after a named normalisation (pids, load base).

## R-list

- R-sn02-1, R-sn02-2, R-sn02-3: as ruled.
- R-sn02-4 (recommend, implemented): a literal `*ADDRESS` breakpoint is absolute.
- R-sn02-5 (recommend, implemented): wolf-binary startup margin 6.0; lazy
  per-unit DWARF loading becomes a follow-up lane.
- R-sn02-6 (recommend, implemented): terminal and batch outputs both match gdb's
  text, but `/usr/lib/` library paths are shown as `/lib/`.
- R-sn02-8 (recommend, implemented): the two `info registers` rows name the 26
  general registers. gdb's bare `info registers` adds `k0`-`k7` on AVX-512
  hosts, which differ by runner (trunk run 42183331207); sniff prints the
  general registers only. The harness already fixes the program's environment
  (`LINES`, `COLUMNS`, `PWD` as gdb adds them), so stack-derived registers are
  stable across parent environments; `session.py oracle` now says what drifted.
- R-sn02-7 (recommend, implemented): `maint frames` is a sniff command outside
  gdb's language, used only as evidence of the unwind basis.

## Done-when

- [x] run and kill; exits and signal deaths as gdb reports them
- [x] breakpoints by function, `file:line`, address; `info breakpoints`, `delete`, hit counts
- [x] `step`, `next`, `finish`, `until`, `continue`, `stepi`, `nexti`
- [x] `bt` by CFI with a stated frame-pointer fallback; `frame`, `up`, `down`
- [x] `print`, `info locals`/`args`, `x`, `info registers` for what the DWARF describes
- [x] hostile and odd inferiors: unmapped breakpoint, own `SIGTRAP`, fork, stripped, death mid-step
- [x] timed rows with stated margins
- [ ] the gauntlet and plant records: in the PR
