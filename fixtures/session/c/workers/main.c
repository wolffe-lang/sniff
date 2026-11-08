// SPDX-License-Identifier: GPL-3.0-or-later
// Three threads beside main. Two spinners loop until they are let go; the worker waits until main and
// both spinners are inside their loops, then calls work(), where the rows put a breakpoint. main waits
// in its own loop, not in the C library, so every thread is in this file when work() stops. Then the
// threads end one at a time, in one order on every host: the worker, the first spinner, the second. main
// joins each and waits until its end has been taken before it lets the next one go (see wait_gone), so a
// debugger sees one end at a time. With the argument "signal" the worker first sends itself SIGUSR1
// (tgkill, made in this file), which main's handler counts.
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static volatile int worked;
static volatile int released;
static volatile int seen[3];
static volatile int signal_mode;
static volatile sig_atomic_t usr1;
static volatile long ids[3];

static void on_usr1(int sig) { usr1++; }

/* The calling thread's id (gettid, made in this file), or 0 where there is none. */
static long self_id(void) {
    long tid = 0;
#if defined(__linux__)
    __asm__ volatile("syscall" : "=a"(tid) : "a"(186L) : "rcx", "r11", "memory");
#endif
    return tid;
}

/* SIGUSR1 to the calling thread alone. */
static void deliver_here(void) {
#if defined(__linux__)
    long pid = getpid(), tid = self_id(), ret;
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
    ids[id - 1] = self_id();
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
    ids[2] = self_id();
    while (!(seen[0] && seen[1] && seen[2])) {}
    if (signal_mode) deliver_here();
    worked = work(n);
    return 0;
}

/* After pthread_join: wait until the thread's end has been taken. pthread_join returns once the thread
 * has left its code, but a tracer is told of the end a little later, and a thread with a tracer keeps its
 * /proc/self/task entry until the tracer has waited for it (proc(5), ptrace(2)). So the next thread is let
 * go only once this one's entry is gone, and a debugger sees the ends in this order on every host. The wait
 * is bounded, for a system whose procfs keeps no such entry. */
static void wait_gone(long tid) {
    char path[64];
    if (tid > 0) {
        snprintf(path, sizeof path, "/proc/self/task/%ld", tid);
        for (int i = 0; i < 2000 && access(path, F_OK) == 0; i++) pause_ms(1);
    }
    pause_ms(20);
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
    wait_gone(ids[2]);
    released = 1;
    pthread_join(a, 0);
    wait_gone(ids[0]);
    released = 2;
    pthread_join(b, 0);
    wait_gone(ids[1]);
    return worked == 10 && usr1 == signal_mode ? 0 : 1;
}
