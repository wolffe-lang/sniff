# S7, first part: ELF core files of Linux programs

The prediction (`tests/s7-prediction.json`) was committed before any code, on trunk `60411374`.

## What was built

| | |
|---|---|
| reader | `src/readers/core.lu` reads an ELF64 x86-64 ET_CORE: its PT_LOAD segments and the notes of its PT_NOTEs, kept as spans. NT_PRSTATUS, NT_PRPSINFO, NT_AUXV, NT_FILE and NT_FPREGSET are decoded only when asked, at the offsets `tools/abi-probe.c` measures and `tools/check-abi.py` holds. There are thirteen refusals by name and caps on segments, notes and mapped files. Unit rows run natively and on the checked machine (`src/core_test.lu`). |
| dump | `sniff dump --notes CORE` uses the pinned `readelf --notes --wide` layout. `tools/dump-matrix.py`'s notes rows run sniff and readelf over every core of the take. |
| session | `src/session/source.lu` carries every memory, register and thread-pointer read; `src/session/core.lu` answers them from a core. The forms are `PROG CORE`, `-c CORE [PROG]` and `core-file [CORE]`, and sniff prints gdb's banner. From the core: bt, frame, up, down, info locals, info args, info registers, x, print, list, info threads, thread N, `info proc mappings`, break and watch. step, next, stepi, finish, until, continue and signal are refused with `The program is not being run.`; kill is refused with `You can't do that without a process to debug.`. detach and `core-file` drop the core; run and attach replace it. |
| rows | The core rows run over 7 cores. The pinned gdb writes each core with gcore in every take, on the Linux set and on the PAX set: static builds, with the cores read at PAX's console. |

## What was measured, and what changed in the design

- gdb's gcore writes one PT_NOTE with p_align 1 and pads its notes at 4. The reader lays notes at 8 only when
  p_align says 8, and refuses any p_align other than 0, 1, 2, 4 or 8.
- gcore leaves whole unmodified file-backed mappings out of the core, among them the C library's text and a
  program's read-only data. Memory comes from a PT_LOAD, else from the file NT_FILE maps there, else is unreadable.
  Without a program, its ranges are read from the path the note names, as gdb does.
- The pinned readelf never decodes NT_FILE: it prints `Cannot decode 64-bit note in 32-bit build`, at gcore's page
  size of 1 and at 4096 alike. The notes rows take that phrase off by name (`nt-file=declined`). A readelf that
  decodes the note makes the row red by name. The table itself is held by gdb's `info proc mappings`.
- gdb places a position-independent program over a core only when its build ID is the core's:
  - a copy under another path is placed
  - another program under the core's path is not
  - the program with its build ID taken out is not

  A program loaded at its own addresses keeps its symbols over any core.
- The Address column of gdb's breakpoint tables is 18 characters wide when a row the table lists has an address,
  and 10 otherwise. Every breakpoint has one. A watchpoint has one only while a process is live. So over a core,
  `info watchpoints` is narrow even when a breakpoint exists, and `info breakpoints` is wide once it lists one. A live
  session's table of watchpoints alone is wide, with or without an earlier breakpoint. Three rows hold this:
  `watch-gcc-only-live`, `watch-gcc-only-fault` and `core-gcc-watch-unlisted-break`. A watchpoint set before `run`,
  and one left after the process exits, are not measured.
- Two cores of the same stop differ in thread and process ids (normalised by `lwp` and `pid`), in thread pointers
  where hosts' stacks differ (`thread-addr`), and in the stack left from before the stop. A local that is not yet set
  at the stop is therefore never printed.

## Boundaries

- Kernel-written cores are unmeasured here: the host's core pattern pipes them away from the container.
- A wolf trap ends in exit status 134 with no signal. Its core is taken at the runtime's `__wolf_rt_trap_at`, whose
  frames are the runtime's Rust code: namespaced names, and frames inlined into it. sniff does not name those yet, so
  there is no wolf trap row; the wolf frames of a core are held by `core-wolf-recursion`.
- `info proc` other than `mappings` over a core, `info files`, `gcore` and `generate-core-file` are not implemented.
  `attach` with a core loaded replaces the core without gdb's build ID warning.
- Mach-O cores (macOS) are the milestone's next part. Cores written by PAX wait for its multiprocessor work.
