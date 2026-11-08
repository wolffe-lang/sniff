// SPDX-License-Identifier: GPL-3.0-or-later
// A long sleeper to attach to. It says it is ready, then ticks N times (argv[1], 100 by default),
// napping 20 ms before each tick with the system call made in this file, so an attach stops it here.
// Then it says how many ticks it made and exits 0: a program a debugger left unharmed ends that way.
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>

static volatile int ticks;

void tick(int n) {
    ticks = n;
}

static void nap(void) {
#if defined(__x86_64__)
    long ts[2] = {0, 20000000}, ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(35L), "D"(ts), "S"(0L) : "rcx", "r11", "memory");
#elif defined(__aarch64__)
    struct timeval tv = {0, 20000};
    register long x0 __asm__("x0") = 0;
    register long x1 __asm__("x1") = 0;
    register long x2 __asm__("x2") = 0;
    register long x3 __asm__("x3") = 0;
    register long x4 __asm__("x4") = (long)&tv;
    register long x16 __asm__("x16") = 93;
    __asm__ volatile("svc #0x80" : "+r"(x0), "+r"(x1) : "r"(x2), "r"(x3), "r"(x4), "r"(x16) : "memory", "cc");
#endif
}

int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 100;
    printf("ready %d\n", (int)getpid());
    fflush(stdout);
    for (int i = 1; i <= n; i++) {
        nap();
        tick(i);
    }
    printf("done %d\n", ticks);
    return 0;
}
