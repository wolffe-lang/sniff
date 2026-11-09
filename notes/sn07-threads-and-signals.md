# sn07: threads and signals (S6, the first of two)

Base: sniff trunk `91d271e`. The prediction was committed before code (`tests/sn07-prediction.json`, `b8774a8`).
S6 asks for multi-threaded programs (all-stop first), `info threads` and `thread N`, signal stops and `handle`,
and `attach` and `detach`, on Linux, macOS and PAX. The prediction measured all of it and found it too large for
one PR, so it is two: this one is threads and signals on all three platforms; attach and detach follow from this
branch's gauntlet-green head, with their own rows, gauntlet and plant.

## What was built

| | |
|---|---|
| threads, Linux and PAX | `src/session/threads.lu` over `src/platform/linux.lu`: `PTRACE_O_TRACECLONE`, and every thread awaited with `__WALL`. A stop stops every other thread: a SIGSTOP to each by `tgkill(2)`, each awaited, and a thread that reports something else first keeps that stop for the next resume. A new thread's first stop may come before the clone event that names it, and is kept until then. gdb's `[New Thread …]`, `[Thread … exited]`, `[Switching to …]` and `Thread N "name" hit Breakpoint …` lines; `info threads [ID…]` in gdb's table; `thread`, `thread N` and their refusals; `bt`, `frame`, `print` and `info locals` in the selected thread |
| target ids and names | gdb's three forms, as measured: `Thread 0x… (LWP n)` where gdb reads the C library's thread records (a dynamic program, or a static one whose symbols carry `_thread_db_*`), else `LWP n` once a second thread exists and `process n` before. The address is the thread pointer (fs_base). The name is the kernel's (`/proc/PID/task/TID/comm`); where PAX keeps none (pax#322) it is the program file's base name cut to 15 bytes, the name Linux gives a thread at exec |
| resuming from another thread | `[Switching to …]` is printed against the thread selected when the command started, so a signal that does not stop on the way leaves it. After `thread 2`, the thread that reported a breakpoint steps past it before every thread resumes |
| threads, macOS | `src/platform/macos.lu`: the task is suspended at each reported exception and resumed with the reply, so every thread stops and runs together. macOS has no thread events: the thread list is read at each stop (`task_threads`) and numbered in the kernel's order, and the thread that took the exception is selected. The reply and a signal's delivery are that thread's, whichever thread is selected. lldb is the oracle there, so the Target Id is sniff's own: `Thread 0x<handle> (tid <id>)`, the handle and the system-wide id from `THREAD_IDENTIFIER_INFO` |
| frames on macOS | a system call's stub outside the program (`svc #0x80` before the pc) keeps no frame, so its caller is in the link register; a return address saved by a system library may be signed (pointer authentication), and only its low 47 bits are the address |
| signals | `src/session/signals.lu` over gdb's table of 149 signals (`src/session/sigtable.lu`, generated from the pinned gdb's `info signals`): `handle SIGNAL… KEYWORD…` with every keyword abbreviable, `all`, gdb's numbers 1-15 and their ranges, and the table printed at a terminal only; `info signals [SIGNAL]` and `info handle`; `signal SIGNAL` and `signal 0`, with `Continuing with …` at a terminal. A signal set to nostop and print is mentioned and the program goes on. Pass is read at the resume, so `handle SIGUSR1 nopass` after the stop decides what `continue` does. A thread's signal stop names the thread before the switch line, the reverse of a breakpoint's order |
| library frames | `src/session/libs.lu`: a frame whose pc is in a shared library is unwound by that library's own `.eh_frame` and named from its symbols (`qsort_r () from /lib/x86_64-linux-gnu/libc.so.6`), or `?? () from LIB` where no sized symbol covers the pc. The library is the file `/proc/PID/maps` names for the pc, read at first sight |
| symbol names | of several symbols at one address, the pinned gdb names the one that sorts last byte by byte (all 240 alias groups of a static C library program, by `info symbol`: `clone3`, not `__clone3`). A name that does not start with `_` loses a compiler's final clone number and shows `.cold` as `[cold]` (`msort_with_tmp.part.0` is `msort_with_tmp.part`; all 175 names with a dot in two static programs) |
| `stepi N` | the place is shown once, where the last step stops, as gdb shows it |
| help | `help handle`, `help signal`, `help thread` and its alias `t`, `help info signals` (and `info handle`) and `help info threads`: gdb's whole text where sniff does all it says, gdb's first lines and sniff's own where it does not (thread's subcommands, `-gid`); the class and `info` listings name them, and none is called a command sniff lacks any more |
| harness | `tools/session.py`: the pid normalisation covers every `process N`; LWP ids are numbered by first appearance; the spin loop's pc prefix and the threads table's padding are normalised by name; tick counts only where a row names them; a thread's address is named by first appearance on every set (`<T1>`, `<T2>`, ...; see "After the merge"). `tools/session-mac.py`: thread facts, the stopping thread, lldb's restarted-signal line, and a thread's status block is no frame fact on either side. The attach runner (the sleeper started as the harness's child, `{pid}` substituted, its end appended) is here for the attach rows that follow |
| ABI | S6's ptrace requests, events and `siginfo_t` offsets, checked against the oracle by `tools/abi-probe.c` (`tests/evidence/linux-s2/abi.txt`) |

Rows: 26 threads rows, 33 signals rows (three at a terminal), 6 library-frame rows and 7 help rows on the session set, the same
on the PAX set, where they also run at PAX's console under KVM. On macOS, 12 lldb fact and expect rows, 11 of
the Linux rows as they are (the refusals and the signal table), and the rest excluded by name with the row that
holds them. Every new row was red at trunk on all three sets but the guards `signals-gcc-run`,
`signals-clang-run` and `lldb-signals-run`, which trunk already got right.

## Prediction against result

- Held:
  - every line form and order the probe measured for gdb and lldb, the threads table's layout and the three
    target-id forms;
  - PAX's `ptrace(2)` answered every call S6 makes as Linux does; its only gaps were the procfs files
    `comm` and `task/TID/stat`, filed as pax#322 with the probe's line as the witness;
  - wolf 0.2.38's std has no threads, and its tasks' worker threads follow the host's CPUs and the scheduler,
    so no wolf thread transcript is stable: the thread rows are C-only until wolf's std has threads;
  - macOS learns of threads from `task_threads` at each stop, as planned.
- Wrong or missed, each now named:
  - the switch line's baseline is the thread selected when the command started, not the thread resumed last
    (`threads-*-signal-nostop`, and `threads-gcc-again` for a second stop in the same thread);
  - `continue` after `thread 2` hit the same breakpoint again until the reporting thread stepped past it
    first (`threads-*-spinner`);
  - the static C library's aliases (`__clone3` and `clone3`) and its clone suffixes (`.part.0`), both now
    measured rules;
  - PAX maps a thread's stack below Linux's `0x7ff…` range, which the PAX set's stack rule did not reach, and a
    host's stack limit moves every thread's address on Linux too (see "After the merge");
  - the thread ends came in the fixture's order on the hosts that took them, but not on every host (see "After the
    merge");
  - lldb prints `thread select`'s status block asynchronously: in one take it came after the next
    command's output, under that command's prompt;
  - under lldb, the threaded signal row's `continue` ended the program with status 1, where it exits 0 natively
    and under a plain run: the row ends with `kill`;
  - the library frames: the pinned C library is built with frame pointers, so the frame-pointer walk already
    found the callers of a library function past its prologue; only a stop at a library function's first
    instruction tells the two apart (`libframes-*-entry`). The names were missing on every set;
  - `stepi N` printed every step.

## Decisions

- Two PRs: threads and signals first, then attach and detach, because attaching to a threaded process attaches
  every thread and a thread's signal stop is printed differently from a lone thread's.
- The thread rows are C-only, for wolf's reason above.
- A shared library's frames are unwound by the library's own `.eh_frame` and named from its symbols, printing
  `?? () from LIB` where none covers the pc, as gdb does.
- On macOS the thread rows are lldb fact rows (each thread's number, function, file and line; the stopping
  thread; the selected thread's frames), and the Target Id is sniff's own.
- Measured but outside the contract's list, and left to the remainder: stepping into a handler,
  `<signal handler called>`, `next` over a handler, `queue-signal` and `thread apply`.

## Remainder

- Stepping into a signal handler, the `<signal handler called>` frame, `next` over a handler, `queue-signal`,
  `thread apply`; `thread name` and `thread find` are named as gdb commands sniff does not implement yet.
- Watchpoints across threads: a watch is armed in the selected thread's debug registers only.
- Non-stop mode and scheduler locking. On Linux and PAX a single step moves the selected thread alone; on macOS
  the other threads run during it.
- Wolf thread rows, when wolf's std has threads.
- macOS: thread names (sniff shows the program's base name, as for a thread with no kernel name), and a
  thread's end is seen at the next stop; a system library's frames beyond a system call's stub and the
  frame-pointer chain (the dyld shared cache has no file to read unwind tables from).
- `step N` and `next N` still show each step's line; gdb's form there was not measured.

## Forbidden

The clean room held. These were read: the GDB manual's Threads, All-Stop Mode, Thread Stops, Signals, Attach,
Kill Process, Background Execution and Interrupted System Calls sections; the man pages `ptrace(2)`, `wait(2)`,
`signal(7)`, `proc(5)`, `proc_pid_task(5)`, `proc_pid_comm(5)`, `proc_pid_stat(5)`, `proc_pid_status(5)`,
`tgkill(2)`, `clone(2)`, `sigaction(2)`, `pthreads(7)`, `prctl(2)` and `kill(2)`, each fetched twice and
digest-checked; the macOS SDK headers' declarations for the task, thread and exception calls. gdb ran only as the
pinned binary in the oracle image and lldb only as the system binary. No debugger's or kernel's source was read.

## After the merge: thread addresses

The first trunk run of the full tier on a hosted runner failed `session-oracle-stable` on 23 threads rows, each at
the second thread's `[New Thread …]` line: the pinned gdb printed `0x7ffff6da06c0` where the goldens, captured on
another host, have `0x7ffff75a06c0`. A thread's address is the C library's record of it, at the top of a stack the
library maps, and the library sizes that stack by the stack limit: there the stack limit was 16 MiB, where the
golden's host has 8 MiB, so the second thread sat 8 MiB lower. The same rows ran red under `ulimit -s 16384` in
the oracle image (23 `oracle-drift` lines, the runner's own), and green again once `tools/session.py` named a
thread's address by first appearance, as it names an LWP id: `Thread <T2> (LWP <L2>)` wherever gdb prints a
thread's target id (`[New Thread …]`, `[Switching to …]`, `info threads`, `[Thread … exited]`, `[Current thread
is …]`). The rule replaces the PAX set's `<STACK>` for thread addresses, so both sets read alike. sniff still prints
the real address, and a thread shown at another thread's address is still told apart. The macOS rows hold no
thread address (lldb fact rows), so nothing there moved.

The same runner then showed a second host dependence: the order of the `[Thread … exited]` lines. The prediction
said they come in the fixture's order, and they did on the two hosts that took them, but on the runner the main
thread's end came before the second spinner's on 17 rows. `pthread_join` returns once a thread has left its
code, before a tracer is told of the end, and main returned right after joining the last spinner: the process's
end and the spinner's raced. Under `taskset -c 0` in the oracle image the pinned gdb showed the runner's order in
each of five takes (`want '[Thread <T2> (LWP <L2>) exited]' got '[Thread <T4> (LWP <L4>) exited]'`, 85 lines),
while sniff's rows held. The fix is in the fixture, so gdb's own transcript has one order: after each join, main
waits until the thread's `/proc/self/task` entry is gone, which for a traced thread is once the tracer has waited
for it, and only then lets the next thread go or returns. The wait is bounded, for a system whose procfs keeps
no such entry, and is a short pause on macOS, where lldb prints no thread ends. The threads goldens and lldb's
thread evidence were re-captured on it, and the second-stop row's breakpoint moved with work's loop to line 64.
No other row depends on threads running in a given order: new threads are announced as main makes them, one at a
time; the stops are the worker's alone; no row lists threads after one has ended or selects an ended thread.

## Done-when

- [x] the prediction before code
- [x] the rows, red against trunk on the Linux, macOS and PAX sets
- [x] threads, all-stop: new threads traced as they start, a stop stops every thread, `info threads` and
  `thread N` with `bt`, `frame` and `print` there, `continue` resuming all, a thread's end, gdb's lines with
  LWP ids and addresses normalised by name
- [x] signals: the stop and its frame line, `handle`, `info signals`, `signal SIG`, `continue` passing the
  signal, the program's own SIGSEGV at the faulting line
- [x] PAX: the rows at PAX's console under KVM, the procfs gap filed as pax#322
- [ ] attach and detach: the second PR
- [ ] the gauntlet, the plant and the macOS record at the head: in the PR
