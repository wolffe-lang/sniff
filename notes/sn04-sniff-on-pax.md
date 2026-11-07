# sn04: sniff on PAX (S4)

S4's done-when: PAX's kernel has `ptrace` (px102), sniff is static on the dev image, and the S2 session typed at
PAX's console is held to Linux byte for byte after the named normalisation. All 141 rows of the S2 matrix run on
PAX under KVM against px102's head and pass. No row is excluded.

## What was built

| | |
|---|---|
| platform layer | none new. PAX answers `ptrace`, `wait4`, `/proc/PID/mem`, `fork` and `execve` as Linux does, so `src/platform/linux.lu` runs unchanged |
| static sniff | `tools/build-static-sniff.sh` (a `cc` that adds `-static` in front of wolf's link; checked `ET_EXEC`, no `PT_INTERP`). The pax-side builder and image hook is a patch file, `tools/mksniff`, `user/sniff.pin` and the `tools/distribution-root` / `tests/distribution` lines, owed to the next stick's lane |
| static fixtures | `tools/build-session.py --static`: C with `-static -no-pie`, wolf through the static `cc`. All 22 programs are `ET_EXEC` |
| goldens | `tests/evidence/pax-linux`, the pinned gdb on those static builds. The dynamic S2 goldens differ by construction (library frames, load addresses) and are untouched |
| row set | `tools/session.py --set pax`; overrides and per-line drops in `tests/pax-rows.json` |
| PAX harness | `tools/session-pax.py`: one image per group of rows (pelt as init, `cat`, `env`, sniff, the fixtures, their sources at the DWARF paths), one typed command line, the console split by marker. `tools/gate-pax` wraps it with END lines |
| terminal rows | `session-pax.py tty`: sniff is init and the commands are typed key by key at its prompt |
| probe | `tests/pax-probe/probe.c`, one line per kernel call; its answers are the gap witnesses |

## Prediction against result (`tests/sn04-prediction.json`, committed first)

- Held: no new platform module; static-only; the S2 rows need only `/proc/PID/mem`; the PIE-address rows were
  rewritten by recapture (the static addresses come from the new goldens); the selector translation (R-px102-1)
  held, cs 0x33 and ss 0x2b read as on Linux; the five terminal rows pass once the console is the terminal.
- Wrong or missed, each now named:
  - sniff itself needed two fixes that the static builds exposed on Linux, before PAX was involved (red at the
    first check, 4 rows): a fully stripped static program has no symbol table at all, so `break main` says
    "No symbol table is loaded." (a dynamic one keeps its dynamic symbols); and `step` out of `main` into libc code
    that an ELF symbol names stops there ("0x... in __libc_start_call_main ()"), while code no symbol names is still
    run on.
  - The first PAX run of the wolf rows failed: a 16 MB wolf binary makes sniff's own `fork` hit PAX's "no frames
    for a copy of the address space". Guest memory 2048M and up passes; the harness boots with 4096M (gap 5).
  - `eflags` joined the libc-residue drops: PF differed in one of the two register rows' builds.

## Normalisations and drops (all named in the PASS lines when they fire)

| name | what | argument |
|---|---|---|
| pid | the N of `(process N)` and `child process N` | an allocation order, not a debugger fact (as S2) |
| stack | hex values 0x7ff... and their decimal forms become `<STACK>` | the stack top depends on the environment and auxv each kernel supplies |
| tty | carriage returns, prompts, the typed echo of the console | the console is a real terminal with its own echo |
| kernel line | `user: ...` console lines (a program killed by a signal) | the kernel's own line; it prints even with `quiet`; gap 6 |
| drop, per line | in `step-*-stepi`: the `<STACK>:` word lines; in `value-*-registers`: rbx rcx rdx rsi r8-r15 fs_base eflags | stack words and libc startup residue; every other line of those rows is held, including rax rdi rbp rsp rip cs ss ds es fs gs |

## SKIPs

None. A row that does not run prints `SKIP name reason=...` or, if it produced no complete block, FAIL `no-result`.
Not on PAX by design: the perf rows (QEMU timing says nothing about sniff) and the lupin join (lupin is another
tool; wolf values on PAX are held to the same gdb goldens).

## The PAX gaps

Seven witnesses, each with PAX's answer and Linux's, are in the lane's gap note for a small px lane: no
`/proc/PID/maps`, `auxv` or `task/TID/stat`, a shorter `/proc/self/stat`, `personality` answering ENOSYS, fork
needing more memory than Linux for a large debugger, and the kernel's kill line under `quiet`. None blocks S4.
For S5-S7: maps and auxv for PIE and shared libraries, `task/TID/stat` for threads, and px102's own list
(refused `SETFPREGS`, `SETREGSET`, `NT_X86_XSTATE`, no Yama).

## R-list

- R-sn04-1 (recommend, implemented): the PAX session runs static builds with goldens from the pinned gdb on those
  same builds, never the dynamic S2 goldens.
- R-sn04-2 (recommend, implemented): drops are per line and named in `tests/pax-rows.json`; no row is excluded.
- R-sn04-3 (recommend, implemented): the hook for the dev image is a patch file for the next stick's lane;
  nothing is committed to the PAX repository.
- R-sn04-4 (recommend): the BACKLOG's bare `info registers` row is not in this lane's path (the PAX session names
  the registers); it stays in the BACKLOG.

## Done-when

- [x] the prediction before code
- [x] sniff static, with the image hook as a patch
- [x] the S2 session on PAX under KVM, red first: the first PAX run failed the wolf rows by name, then green
- [x] the PAX gaps as witnesses
- [ ] the gauntlet, the plant record and the PAX records at the rebased head: in the PR
