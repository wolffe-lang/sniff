// SPDX-License-Identifier: GPL-3.0-or-later
// The program sends itself SIGUSR1, SIGUSR2 and SIGUSR1 again, each with the kill system call made in
// this file (no C library frame lies between a signal stop and this file). Its handlers count what
// arrives, and the exit code says what the program saw: ten times the SIGUSR1s plus the SIGUSR2s, 21
// when every signal reached it.
#include <signal.h>
#include <unistd.h>

static volatile sig_atomic_t usr1, usr2;

static void on_usr1(int sig) { usr1++; }
static void on_usr2(int sig) { usr2++; }

static void deliver(int sig) {
    long pid = getpid();
#if defined(__x86_64__)
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(62L), "D"(pid), "S"((long)sig) : "rcx", "r11", "memory");
#elif defined(__aarch64__)
    register long x0 __asm__("x0") = pid;
    register long x1 __asm__("x1") = sig;
    register long x2 __asm__("x2") = 1;
    register long x16 __asm__("x16") = 37;
    __asm__ volatile("svc #0x80" : "+r"(x0), "+r"(x1) : "r"(x2), "r"(x16) : "memory", "cc");
#endif
}

int main(void) {
    signal(SIGUSR1, on_usr1);
    signal(SIGUSR2, on_usr2);
    deliver(SIGUSR1);
    deliver(SIGUSR2);
    deliver(SIGUSR1);
    return usr1 * 10 + usr2;
}
