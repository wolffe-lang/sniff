#!/usr/bin/env python3
"""A stand-in for PAX's tools/qemu-run, for session-dap.py's units, never QEMU: qemu-run --accel A --gdb PORT
--timeout SECONDS --serial FILE IMAGE

It boots nothing. It listens on 127.0.0.1:PORT as QEMU's gdbstub would, accepting and closing connections, until
SECONDS pass or it is ended. An IMAGE whose bytes say `silent` never listens (a boot that never reaches the stub)."""
import argparse
import socket
import sys
import time

p = argparse.ArgumentParser()
p.add_argument('--accel', required=True)
p.add_argument('--gdb', type=int, required=True)
p.add_argument('--timeout', type=float, default=300)
p.add_argument('--serial', required=True)
p.add_argument('image')
a = p.parse_args()
end = time.time() + a.timeout
if b'silent' in open(a.image, 'rb').read():
    while time.time() < end:
        time.sleep(0.1)
    sys.exit(0)
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', a.gdb))
s.listen(4)
s.settimeout(0.2)
while time.time() < end:
    try:
        c, _ = s.accept()
        c.close()
    except socket.timeout:
        pass
