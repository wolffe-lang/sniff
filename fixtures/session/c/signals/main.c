// SPDX-License-Identifier: GPL-3.0-or-later
// The program installs its own SIGTRAP handler and executes int3 itself.
#include <signal.h>

static volatile sig_atomic_t seen;

static void on_trap(int sig) {
    seen = sig;
}

int main(void) {
    signal(SIGTRAP, on_trap);
    __asm__ volatile("int3");
    return seen == SIGTRAP ? 0 : 1;
}
