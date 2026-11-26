# Both sides of the pinned gdb's launch-start race

Two takes of the row `dap-launch-env`, recorded by `tools/session-dap.py capture` from the pinned gdb 15.1 in DAP
mode (`gdb -i=dap`, binary sha256 `3832cc07...`) in one capture over gcc's `c/where`, one on each side of a race
inside gdb:

- `requests-first.jsonl`: gdb answered the breakpoint request at a library-load stop, before the program reached
  main, and answered `configurationDone` notStopped.
- `main-first.jsonl`: gdb answered the breakpoint request at the stop in main, answered `configurationDone`
  success, and echoed its own `Breakpoint 2 at ...` line as an `output` event.

gdb starts the program at launch and answers these requests only at a stop. Which side a take falls on follows gdb's
ordering and the host's load, not the program. The rows name the difference (`breakpoint-echo`, with
`launch-start`), and these takes hold the comparison to it in `tests/test_session_dap.py`. The main-first side is
kept here because a capture in a quiet slot does not produce it.
