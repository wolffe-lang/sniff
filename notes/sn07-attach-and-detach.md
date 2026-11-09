# sn07: attach and detach (S6, the second of two)

Base: sniff trunk `6309819`, after threads and signals (`notes/sn07-threads-and-signals.md`). The prediction
for both parts was committed before code (`tests/sn07-prediction.json`, `b8774a8`). This part is `attach PID`,
`detach` and `sniff -p PID`, with their refusals, on Linux, macOS and PAX.

## What was built

| | |
|---|---|
| commands | `src/session/attach.lu`: `attach PID` traces the process and every thread it has, stops it where it is and shows that place as gdb does; `detach` lets it go on untraced with `[Inferior 1 (process N) detached]`; `sniff -p PID PROG` attaches before the command file runs. A session that ends with a process it attached to detaches from it, where a program it started is killed; `kill` kills an attached process as it kills a started one. At a terminal, gdb's `Attaching to program: …`, `Reading symbols from LIB...` and `(No debugging symbols found in LIB)` for each mapped library in address order, and `Detaching from program: …` |
| refusals | `Argument required (process-id to attach).`, `Illegal process-id: WORD.`, and `detach` with nothing: `The program is not being run.`, as gdb words them. A refused attach prints `ptrace: TEXT.` with the C library's text for the errno the kernel gave (`No such process`, `Operation not permitted`); when another tracer holds the process it is preceded by gdb's `warning: process N is already traced by process M`, from `TracerPid` in `/proc/PID/status`. `attach` while a program runs is refused with sniff's own `A program is being debugged already.`, where gdb asks a question a command file cannot answer |
| Linux and PAX | `src/platform/linux.lu`: `PTRACE_ATTACH` of the leader, awaited with `__WALL`, then of each other thread in `/proc/PID/task`; the fork, vfork and clone options as for a started program but without `PTRACE_O_EXITKILL`, so the process outlives sniff. Detach is `PTRACE_DETACH` of every thread, the leader last. The threads it had are numbered in the order of their ids and get no `[New …]` line |
| macOS | `src/platform/macos.lu`: `task_for_pid`, sniff's exception port on the task, `PT_ATTACHEXC`, and the SIGSTOP's exception taken as the attach's stop, the task suspended as at every stop. A refused task port is `No such process` when the pid is gone and `Operation not permitted` otherwise (a hardened target). Detach and kill follow the orders a probe measured ("Attach on macOS" below) |
| help | `help attach` and `help detach` hold gdb's summary line and say what sniff does: a process id only, and detach's subcommands as not implemented yet; neither is listed as a command sniff lacks any more |
| harness | the attach runner from the first part, now waiting until the sleeper blocks in its nap before a debugger starts ("Determinism" below). `tools/session-mac.py`: lldb's `stop reason = signal SIGSTOP` at `process attach` is the attach's stop, not a signal fact; an attach row's breakpoint addresses are not compared (its number, file and line are), as macOS maps a process a debugger did not start at an address it chooses. `tools/session-pax.py`: the sleeper is started at PAX's console by its shell, a held row's image carries the holder, and every wait for a line is bounded |

Rows: 15 attach and detach rows, a terminal row and 2 help rows on the session set; the same on the PAX set,
where they also run at PAX's console under KVM but for the terminal row, skipped by name there (the console's
terminal rows run sniff as init, with no shell to start a sleeper). On macOS, 6 lldb fact rows (attach then
detach, a breakpoint after attach, kill, the script's end, continue to the end, `-p`), the hardened refusal, and
6 of the Linux rows as they are (the three refusals, `detach` with nothing, the two help rows); the two clang
rows whose frames are arm64's are excluded by name, held by the lldb rows. Every new row was red at trunk on all
three sets.

## Prediction against result

- Held:
  - gdb's lines, batch and at a terminal, the stop's frame line mid-line after the system call, `-p`, the
    refusals' text, `info threads` after an attach (a dynamic program's `Thread 0x… (LWP n)`), `kill` and the
    end of a script detaching;
  - lldb's facts for the same, and which targets macOS gives a task port to: a target signed with
    get-task-allow is attached to, a hardened one is refused to every debugger;
  - PAX's ptrace attached, detached and refused as Linux does, and its `/proc/PID/status` carries `TracerPid`,
    so the held row prints the same warning there;
  - the rows ran in the oracle container, which gives the debugger `CAP_SYS_PTRACE` in its user namespace; no
    host setting was read or changed.
- Wrong or missed, each now named:
  - at PAX's console five attach rows printed no result: the held row's holder was not in the console's image,
    and pelt's loop reading the sleeper's ready line had no bound, so a missing line grew it until the guest ran
    out of memory. The image now carries each held row's holder and every wait is bounded (400 reads), both held
    by the PAX selftest;
  - lldb reports the attach's own stop as a SIGSTOP; the macOS facts read it as a signal stop that sniff had not
    reported. It is now no signal fact, and a SIGSTOP the program takes later still is;
  - macOS randomises the addresses of a process it did not start for a debugger, so an attach row's breakpoint
    address differed from take to take;
  - sniff's first macOS detach answered the attach's stop and then asked for `PT_DETACH`, which refused (EBUSY),
    and the process was killed when sniff exited; its first kill left a process attached to suspended, and its
    parent saw it exit with status 0 and no output. Both now follow the measured orders;
  - on one CPU, sniff, quicker to start than gdb, attached twice in 55 attaches while the sleeper was still
    inside the `write()` of its ready line, and printed `write () from …/libc.so.6` where gdb shows `nap ()`
    ("Determinism").

## Attach on macOS

`ptrace(2)` on macOS says `PT_DETACH`, like every request but `PT_ATTACHEXC`, needs a process that is stopped
(EBUSY otherwise). A probe (a C program from the SDK's declarations, attaching as sniff does to a sleeper signed
with get-task-allow) measured what that means under `PT_ATTACHEXC`, where a signal is delivered
to the debugger as an exception:

- At the attach's SIGSTOP exception, unanswered, `PT_DETACH` succeeds and the sleeper runs on to `done 100`.
  Answered first (its signal dropped, the task resumed), the process is no longer stopped: `PT_DETACH` gives
  EBUSY, and a process still traced when its tracer exits is killed (SIGKILL).
- At a breakpoint or step exception the process is not stopped either: `PT_DETACH` gives EBUSY. Sending it a
  SIGSTOP, answering the pending exception and taking the SIGSTOP's exception gives the stop `PT_DETACH` needs.
- `kill(SIGKILL)` with the task suspended and the exception pending reaped nothing; once sniff exited, the
  sleeper's parent saw it exit with status 0. With the exception port taken off first, then SIGKILL, the pending
  exception answered and the task resumed, the debugger's `waitpid` sees SIGKILL and so does the parent, from
  either stop. With the port left on, SIGKILL from a breakpoint stop came back as one more exception.

So detach sends a SIGSTOP unless the pending exception is one, waits for that exception, asks for `PT_DETACH`
first, and only then takes the port off, answers and resumes; kill takes the port off, sends SIGKILL, answers and
resumes. lldb's own detach and kill end the sleeper the same way (`done 100`; `killed by signal 9`), the rows'
fact.

## Determinism

Each attach row starts its own sleeper, so where an attach lands is the one place timing could enter a row. The
sleeper's nap is the only place it blocks, but its ready line is written by a system call too, and the harness read
that line and started the debugger at once. Five takes of the attach rows and the pinned gdb on one CPU of the
oracle image caught sniff in `write()` twice in 55 attaches (`attach-clang-break`, `attach-gcc-dash-p`), where a
take on six CPUs had not: gdb, which reads symbols before it attaches, never was. Now the harness waits, bounded,
until the sleeper blocks: `State: S` in `/proc/PID/status` on Linux and at PAX's console (where the state seen is
printed on the console, outside the row's result), `ps -o stat=` on macOS. If the nap ends between the wait and the
attach, the stop comes as the system call returns, on the same line; only the few instructions between two naps are
elsewhere. Then, in the oracle image, the attach rows and gdb's stability check ran ten times on one CPU and five
times on six, each take 18 of 18 and gdb stable; the rows ran at PAX's console, where every attach row's sleeper
was in state S at the first read (`@@WAIT S 1`), 17 of 17 with the terminal row skipped by name; and the macOS
attach rows ran three times, 13 of 13 each. The tick a breakpoint after an attach lands on is timing, and the rows
that name it normalise it by name, as planned.

The development wrapper that ran these takes reported a job green over a failing row: each step's own END line
said `exit=1`, but the job's ended `exit=0`. Its steps now record the worst status and the job ends with it; on the
plant's head it ended `exit=1` at `attach-gcc-quit`.

## Decisions

- The not-permitted refusal. The pinned gdb prints a distribution's three-line ptrace-scope paragraph
  on stdout and `ptrace: Inappropriate ioctl for device.`, an errno left by a later call, not the attach's.
  sniff prints gdb's already-traced warning and the errno the kernel gave the attach, `ptrace: Operation not
  permitted.`; the row (`attach-gcc-held`) holds sniff's own text, names the divergence in its `why`, and checks
  that gdb's golden refuses the attach too.
- On macOS the attach rows are lldb fact rows, as the thread rows are.
- A process sniff attached to is detached at the session's end, never killed, as gdb does.

## Remainder

- `attach` with no program file (gdb finds it from the pid), `sniff PROG PID`, and `attach` while a program
  runs (gdb asks to kill it first).
- `detach inferiors` and `detach checkpoint`.
- A signal pending at detach is dropped, where gdb may pass it; at a macOS breakpoint stop the SIGSTOP that
  detach sends is the process's last signal seen.
- macOS: no library lines at a terminal (the system libraries are in the dyld shared cache, with no file to name).
- PAX: the terminal attach row, until the console's terminal rows have a shell.

## Forbidden

The clean room held. These were read: the GDB manual's Attach and Kill Process sections (with the first part's
list); the man pages `ptrace(2)`, `wait(2)`, `proc(5)`, `proc_pid_task(5)` and `proc_pid_status(5)` from
man7.org, fetched and digest-checked as listed in `docs/SOURCES.md`, and the macOS SDK's `ptrace(2)` man page;
the macOS SDK headers' declarations for `task_for_pid`, the exception ports and `ptrace`. gdb ran only as the
pinned binary in the oracle image and lldb only as the system binary. No debugger's or kernel's source was read.

## Done-when

- [x] `attach PID`, `detach` and `sniff -p PID` on Linux, macOS and PAX, with rows proving the program runs on
  unharmed after `detach` (`done 100`)
- [x] refusals by name: no such process, not permitted (another tracer; a hardened macOS target), and the
  command's own
- [x] PAX: the batch rows at PAX's console under KVM, the terminal row skipped there by name
- [x] the rows, red against trunk on the Linux, macOS and PAX sets
- [x] determinism: one CPU and many, before the records
- [x] the gauntlet, the plant and the macOS record at the head: in sniff#17, with the hosted full gate green

**S6 is met:** multi-threaded programs all-stop, `info threads` and `thread N`, signal stops and `handle`,
`attach PID`, `detach` and `sniff -p PID`, on Linux x86-64, macOS arm64 and PAX (sniff#15, sniff#16 and sniff#17).
