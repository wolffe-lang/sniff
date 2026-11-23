// SPDX-License-Identifier: GPL-3.0-or-later
// A call through a null function pointer: the processor jumps to address 0, below a position-independent
// program's load address, and faults there with the caller's return address on the stack.
typedef int (*handler)(int);

int apply(handler h, int v) {
    return h(v);
}

int main(int argc, char **argv) {
    (void)argv;
    handler volatile h = 0;
    return apply(h, argc);
}
