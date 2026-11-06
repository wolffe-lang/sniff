# sn03: macOS arm64 (S3)

Base: sniff trunk `fc856c6` (sn02 merged as sniff#4, `info registers` fix as sniff#7). The prediction was
committed before code (`tests/sn03-prediction.json`, `32e473e`). The S2 command set runs on macOS arm64
unchanged above `src/platform/`.

## What was built

| piece | file | how |
|---|---|---|
| process layer | `src/platform/macos.lu` | `posix_spawn` with `POSIX_SPAWN_START_SUSPENDED` and `_POSIX_SPAWN_DISABLE_ASLR`; `task_for_pid` on the child; one exception port (`task_set_exception_ports`, bad access, bad instruction, arithmetic, breakpoint, software); `ptrace(PT_ATTACHEXC)` so Unix signals arrive as exceptions; `thread_get_state` with `ARM_THREAD_STATE64`; `mach_vm_read_overwrite`, `mach_vm_write`, `mach_vm_protect` (copy-on-write for text); single step is `MDSCR_EL1.SS` through `ARM_DEBUG_STATE64` |
| per-architecture hooks | `src/platform/arch.lu` | the breakpoint instruction (`BRK #0xf000`, `0xd43e0000`), the pc after a trap, the register set |
| arm64 unwinding | `src/session/arm64.lu` | compact unwind (`__unwind_info`, R-sn00-2), a prologue and epilogue analysis, the x29 chain; `maint frames` names the basis per frame |
| Mach-O and dSYM | `src/session/program.lu` | the image paired with its dSYM by UUID (`macho_match_uuid`); a missing or mismatched dSYM is refused by name |
| arm64 `info registers` | `src/session/inspect.lu` | x0-x28, fp, lr, sp, pc, cpsr in gdb's aarch64 columns |
| signing | `tools/sign-sniff.sh`, `tests/debugger.plist`, `tests/get-task-allow.plist` | sniff ad hoc with `com.apple.security.cs.debugger`; fixtures ad hoc with `get-task-allow` |
| rows | `tests/macos-rows.json`, `tools/session-mac.py` | see below |

## Signing, measured

On this Mac (`DevToolsSecurity` reports disabled, the account is in `_developer`), with no `sudo` and no
setting changed:

- a target signed with `get-task-allow` is granted to an unsigned caller;
- a target without it is refused (`KERN_FAILURE`) unless the caller carries the debugger entitlement, which
  works with `DevToolsSecurity` still reporting disabled;
- a target whose signature was removed behaves as an unentitled one: the kernel still runs the
  linker-signed image, and `task_for_pid` is refused.

So no one-time maintainer step is needed and there is no R-sn03 ruling on signing. The refusal text is
`task_for_pid refused: the target lacks the get-task-allow entitlement (sign it ad hoc with it)`. Sources:
`docs/SOURCES.md`.

## Platform facts that shaped the code

- **BRK.** `BRK #0xf000` (what lldb inserts, read from its transcripts' stop addresses). After the trap the
  pc names the `BRK` itself (an arm64 exception reports the instruction), so no pc adjustment, unlike
  `int3`. A `BRK` that is not one of sniff's own (the program's) is stepped past on resume.
- **A program's own trap.** `signals` stops at the `BRK`'s line (13), where the Linux golden stops after
  the `int3` (14). lldb stops at 13 as well (`lldb-own-trap`). Continuing, sniff follows gdb's default
  (SIGTRAP is not passed: the program runs on); lldb re-stops at the same instruction. The rows compare
  up to the stop, and sniff's continue is held by the Linux row `odd-clang-signal-continue`.
- **ASLR off.** The child starts with `_POSIX_SPAWN_DISABLE_ASLR`, as lldb's runs show (unslid addresses),
  so an absolute `break *ADDR` row means the same thing before and after `run`.
- **A traced parent's `waitpid` returns `EINTR`** when its child exits (the SIGCHLD stop interrupts the
  wait). lldb does the same (the fork fixture exits 1 under lldb). The fixture now retries on `EINTR`; it
  is otherwise unchanged and its line numbers are the same on Linux.
- **Fork.** A forked child inherits the exception port and the parent's inserted `BRK`s. The first inherited
  `BRK` trap in a child is taken as a fork event: the layer keeps the request, the session writes the
  original instructions into the child's task (the same code as Linux), prints
  `[Detaching after fork from child process N]`, and the layer replies so the child retries the original
  instruction. The prediction expected this to be impossible; the child's task port arrives in the
  exception message, which made it possible. A fork whose child never reaches a breakpoint is not seen,
  and prints nothing. Neither sniff nor the parent hangs, and the child runs to completion.
- **Frame names.** The caller of `main` is `dyld`start` in lldb. sniff prints `?? ()`: it does not
  symbolicate system images until S6, as Linux does not name libc.

## Unwinding: which frames use which basis

Measured by `tools/session-unwind.py --platform macos` (gate step `session-unwind-basis`).

| program | frames |
|---|---|
| clang -O0 C (`c/calls`) | `compact` from `__unwind_info` (no DWARF CFI FDEs, R-sn00-2); `main` is the outermost sniff shows |
| wolf 0.2.37 | `frame-pointer` (no CFI and no compact unwind), exactly as on Linux; `main` is outermost |

The `prologue` basis covers a pc inside a function's first instructions (before `stp x29, x30`) or its
epilogue; `frame-pointer` is used only where neither compact unwind nor the prologue analysis covers the pc.

## Rows

`tests/macos-rows.json` holds three kinds of row, run by `tools/session-mac.py check`:

- **linux** (84): the S2 row of the same name run by sniff on the Mac and compared with sn02's recorded gdb
  output after named normalisations (`root`, `addr`, `off`, `pid`). Where a line cannot agree, the row
  names the line or the pattern and why under `drop`; the rest of the row still has to match. Where an x86-64
  register name appears, the row carries its own arm64 script.
- **lldb** (14): a sniff script and an lldb script for the same program, each reduced to facts by a named
  extraction (`bpset`, `frame`, `print`, `retval`, `var`, `exit`, `signal`, `died`, `pc`). lldb's
  transcripts are stored in `tests/evidence/macos-s3` (`capture`), so extraction replays without lldb
  (`replay`, gate step `macos-lldb-replay`, runs anywhere). lldb repeats the stop location after every
  resume and the stop reason under `bt`; the extraction takes frames from `frame`/`bt` output and signals
  from the resuming command only. Two normalisations are named: `char` (lldb prints `'z'`, gdb `122 'z'`)
  and the exit of a process lldb killed at quit (not a program fact).
- **expect** (3): hostile inputs. An unentitled target and a target with its signature removed are refused
  by name; a breakpoint in unmapped memory reports `Cannot access memory at address`.

Rows excluded whole: `value-clang-registers` (x86-64 register names; the arm64 set is held by
`lldb-registers` and by `step-clang-stepi`'s arm64 script).

Dropped lines, each with its reason in the row:

| row | what | why |
|---|---|---|
| `odd-clang-signals` | stop line 13 against 14 | `BRK` leaves the pc on itself; lldb agrees with sniff (`lldb-own-trap`) |
| `step-clang-calls` | `15 }` | clang for arm64 gives the loop body's closing brace its own line-table row; `until` goes forward to it. lldb's `next` goes 14, 15, 13 (`lldb-until-loop`), so this is not a sniff bug |
| `step-clang-calls`, `step-clang-off-main-next` | the caller of `main` | lldb names `dyld`start`; Linux `?? () from libc`; sniff `?? ()` |
| `step-clang-stepi`, `odd-clang-stripped-addr` | the `pc` against `rip` line | register name |
| `odd-clang-stripped-addr` | the header symbol | a stripped Mach-O keeps its exported header symbol, and sniff names a pc after the nearest symbol |
| `wolf-break-main-two-locations` | location `1.2` | the offset inside `main` is arm64's prologue |
| `wolf-scalars`, `wolf-nested`, `wolf-recursion`, `wolf-exits-code` | one line each, by line number | the line reads uninitialised stack. The initialised values of these programs are held to lupin by `session-lupin-join` on the Mac |

## Held to lupin

`session-lupin-join` (`tools/session-values.py`) runs unchanged on macOS: every wolf local sniff prints at a
stop is compared with lupin's value for the same stop (15 stops of `wolf/loops` matched, 41 values agreed).

## Measured

`tools/session-perf.py`, interleaved against lldb on this Mac, ratios of the minimum of nine runs:

| row | lldb | sniff | ratio | margin |
|---|---|---|---|---|
| startup to first breakpoint (C) | 0.313 s | 0.003 s | 0.01 | at most 1.00 |
| startup, large wolf DWARF | 0.317 s | 0.042 s | 0.13 | at most 6.00 (R-sn02-5) |
| 10,000-hit loop | 8.692 s | 0.115 s | 0.01 | at most 2.00 |

## Hosted CI

Hosted macOS CI runs `macos-rows-inventory` and `macos-lldb-replay` (no process, no lldb), `platform-live`,
and the S1 steps that were already oracle-free. `macos-rows`, `session-lupin-join`, `session-unwind-basis`
and `session-perf` print `SKIP <step> reason=hosted-ci: ...` by name under `SNIFF_HOSTED_MACOS_CI=1`: they need
task ports for signed children and the pinned lldb, and run in the Mac's local gauntlet record.

## For S4 (PAX) and S5

Shared by all three platforms: the session layer (`src/session`), the row mechanism (goldens plus
normalisation plus named drops), the lupin join, the `maint frames` evidence. Per platform: `src/platform/*`
and `arch.lu` (the breakpoint instruction, the pc after a trap, the register set, the call detection), the
unwinder's non-CFI bases (`arm64.lu`; x86-64's frame-pointer fallback), signing (macOS only).

- **sn04 first items (PAX).** (1) wait for px102's `ptrace`; (2) a platform layer over PAX's requests, the
  same primitives as `macos.lu`'s list: spawn stopped, wait and decode, resume with a signal, single step,
  memory and register read and write, detach a fork; (3) static sniff on the dev image; (4) the same rows
  at the console against the Linux goldens with a named normalisation (pid, load base); (5) take the
  `drop` mechanism, not whole-row exclusions, for any line PAX cannot match.
- **S5 (watchpoints and expressions) on macOS.** arm64 `DBGWVR`/`DBGWCR` through `ARM_DEBUG_STATE64`, the
  same state block single step uses; the hardware watchpoint exception arrives as `EXC_BREAKPOINT` with a
  data-abort subcode; the number of usable watch registers is read from the state, not assumed.

## R-list

- R-sn03-1 (accepted): after a fault or the program's own `BRK`, `continue` does what gdb does: it delivers
  the signal, and does not pass `SIGTRAP`. lldb stops again at the same instruction. The rows compare up to the stop.
- R-sn03-2 (accepted): a forked child that reaches an inherited breakpoint is detached, with its original
  instructions put back first. The fork fixture's `waitpid` retries on `EINTR`, because a traced parent's wait
  is interrupted when its child exits (lldb does the same).

## The lost hit

An intermittent lost hit in the 10,000-hit loops was a stale instruction cache: every `mach_vm_write` of `BRK`
succeeded, yet the child kept running the old bytes and exited without the trap. Arm requires a data-cache
clean and instruction-cache invalidate before modified code is fetched; `target_write` now asks the kernel with
`mach_vm_machine_attribute(MATTR_CACHE, MATTR_VAL_ICACHE_FLUSH)` (`mach/vm_attributes.h`). `tools/bp-stress.sh`
(gate step `bp-stress`, 200 runs) was red at `d45d30f` (122 of 200) and reads 0 misses of 400 after the fix.
The trace run lost 45 of 200 against the stress run's 122 of 200; that rate difference is unexplained.

## Done-when

- [x] the prediction before code; platform layer; arm64 registers, `BRK`, compact unwind
- [x] Mach-O plus dSYM by UUID; ad-hoc signing
- [x] the S2 matrix on macOS: Linux-compare rows and lldb-fact rows, lupin join
- [x] hostile and odd inferiors
- [x] measured against lldb
- [ ] the gauntlet and plant records: in the PR
