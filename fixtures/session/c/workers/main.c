// SPDX-License-Identifier: GPL-3.0-or-later
// Three threads beside main. Two spinners loop until they are let go; the worker waits until main and
// both spinners are inside their loops, then calls work(), where the rows put a breakpoint. main waits
// in its own loop, not in the C library, so every thread is in this file when work() stops. Then the
// threads end one at a time, in a fixed order: the worker, the first spinner, the second. With the
// argument "signal" the worker first sends itself SIGUSR1 (tgkill, made in this file), which main's
// handler counts.
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static volatile int worked;
static volatile int released;
static volatile int seen[3];
static volatile int signal_mode;
static volatile sig_atomic_t usr1;

static void on_usr1(int sig) { usr1++; }

/* SIGUSR1 to the calling thread alone. */
static void deliver_here(void) {
#if defined(__linux__)
    long pid = getpid(), tid, ret;
    __asm__ volatile("syscall" : "=a"(tid) : "a"(186L) : "rcx", "r11", "memory");
    __asm__ volatile("syscall" : "=a"(ret) : "a"(234L), "D"(pid), "S"(tid), "d"(10L) : "rcx", "r11", "memory");
#else
    pthread_kill(pthread_self(), SIGUSR1);
#endif
}

/* Loop until *flag reaches want. seen[slot] says the loop has been entered. */
static void spin(volatile int *flag, int want, int slot) {
    while (*flag < want) seen[slot] = 1;
}

static void pause_ms(long ms) {
    struct timespec ts = {0, ms * 1000000};
    nanosleep(&ts, 0);
}

static void *spinner(void *arg) {
    int id = *(int *)arg;
    spin(&released, id, id);
    return 0;
}

int work(int n) {
    int total = 0;
    for (int i = 1; i <= n; i++)
        total += i;
    return total;
}

static void *worker(void *arg) {
    int n = *(int *)arg;
    while (!(seen[0] && seen[1] && seen[2])) {}
    if (signal_mode) deliver_here();
    worked = work(n);
    return 0;
}

int main(int argc, char **argv) {
    pthread_t a, b, w;
    int one = 1, two = 2, four = 4;
    signal_mode = argc > 1 && strcmp(argv[1], "signal") == 0;
    signal(SIGUSR1, on_usr1);
    if (pthread_create(&a, 0, spinner, &one)) return 2;
    if (pthread_create(&b, 0, spinner, &two)) return 2;
    if (pthread_create(&w, 0, worker, &four)) return 2;
    spin(&worked, 1, 0);
    pthread_join(w, 0);
    pause_ms(20);
    released = 1;
    pthread_join(a, 0);
    pause_ms(20);
    released = 2;
    pthread_join(b, 0);
    return worked == 10 && usr1 == signal_mode ? 0 : 1;
}
