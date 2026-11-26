#!/usr/bin/env python3
"""A stand-in for the sleeper fixture, for session-dap.py's units, never a debugger's target: standin_sleeper.py N

It says `ready PID`, sleeps N times 20 ms (so it is found sleeping, as the sleeper is in its nap), then says `done N`
and exits 0, as the sleeper does when a debugger left it unharmed."""
import os
import sys
import time

n = int(sys.argv[1]) if len(sys.argv) > 1 else 100
print('ready %d' % os.getpid(), flush=True)
for _ in range(n):
    time.sleep(0.02)
print('done %d' % n, flush=True)
