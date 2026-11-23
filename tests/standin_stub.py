#!/usr/bin/env python3
"""A stand-in remote stub for the harness's units, never a debugger: standin_stub.py MODE [--once] HOST:PORT PROG...

It prints `Listening on HOST:PORT` as sniff-server does and takes one client. MODE close closes that client at once.
MODE oracle and MODE other answer the packets the x87 tag row sends (qSupported, ?, Hg, g, G, k) with fixed replies:
a register file of zero bytes but fctrl, 0x037f under oracle and 0x0000 under other, so the two differ only there.
`--version` prints one line and ends, for the harness's ORACLES line."""
import socket
import sys

FCTRL = 244  # the byte offset of fctrl in the g packet (session-remote.py's G_FCTRL)


def frame(data):
    b = data.encode()
    return b'$' + b + b'#' + ('%02x' % (sum(b) % 256)).encode()


def packets(c):
    buf = b''
    while True:
        chunk = c.recv(4096)
        if not chunk:
            return
        buf += chunk
        while True:
            i = buf.find(b'$')
            j = buf.find(b'#', i + 1) if i >= 0 else -1
            if i < 0 or j < 0 or len(buf) < j + 3:
                break
            yield buf[i + 1:j].decode()
            buf = buf[j + 3:]


def main():
    args = sys.argv[1:]
    if '--version' in args:
        print('stand-in stub 0')
        return 0
    mode = args[0]
    addr = [x for x in args[1:] if ':' in x][0]
    host, port = addr.rsplit(':', 1)
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, int(port)))
    s.listen(1)
    print('Listening on %s:%s' % (host, port), flush=True)
    c, _ = s.accept()
    if mode == 'close':
        c.close()
        return 0
    regs = bytearray(600)
    regs[FCTRL:FCTRL + 2] = (0x037f if mode == 'oracle' else 0).to_bytes(2, 'little')
    for p in packets(c):
        c.sendall(b'+')
        if p == 'k':
            break
        if p.startswith('qSupported'):
            reply = 'PacketSize=1000'
        elif p == '?':
            reply = 'T05thread:1;'
        elif p.startswith('H'):
            reply = 'OK'
        elif p == 'g':
            reply = regs.hex()
        elif p.startswith('G'):
            regs = bytearray(bytes.fromhex(p[1:]))
            reply = 'OK'
        else:
            reply = ''
        c.sendall(frame(reply))
    c.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
