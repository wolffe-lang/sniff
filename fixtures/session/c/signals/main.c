// SPDX-License-Identifier: GPL-3.0-or-later
// The program installs its own SIGTRAP handler and executes a trap instruction itself.
#include <signal.h>
#ifndef TRAP_INSN
#define TRAP_INSN "int3"
#endif
static volatile sig_atomic_t seen;
static void on_trap(int sig) {
    seen = sig;
}
int main(void) {
    signal(SIGTRAP, on_trap);
    __asm__ volatile(TRAP_INSN);
    return seen == SIGTRAP ? 0 : 1;
}
