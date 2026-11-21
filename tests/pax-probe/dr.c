/* PAX's debug registers through ptrace(2), the facts sniff's watchpoints use, one per line. Run the same static
 * build on Linux and at PAX's console: the Linux lines are this probe's golden, and a PAX-set row skipped for
 * "no debug registers" stands only while PAX's lines differ from them.
 *
 * The calls are the ones src/platform/linux.lu makes for a watchpoint: POKEUSER of DR7 (off), of DR0 (the place)
 * and of DR7 (slot 0 on: local enable, the condition, the length); PEEKUSER of DR6 at the stop (B0) and POKEUSER of
 * DR6 back to 0. The offsets come from struct user's u_debugreg as compiled here, never from header text. No
 * address is printed. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile int counter;

static long dr_off(int n) { return (long)(offsetof(struct user, u_debugreg) + n * sizeof(long)); }

static void poke(pid_t c, int n, unsigned long v, const char *what) {
    errno = 0;
    long r = ptrace(PTRACE_POKEUSER, c, (void *)dr_off(n), (void *)v);
    printf("pokeuser dr%d %s -> %ld errno %d\n", n, what, r, r ? errno : 0);
}

static void resume_and_report(pid_t c, const char *what) {
    int st = 0;
    ptrace(PTRACE_CONT, c, 0, 0);
    if (waitpid(c, &st, 0) != c) { printf("%s: waitpid failed\n", what); return; }
    if (WIFSTOPPED(st)) {
        errno = 0;
        long dr6 = ptrace(PTRACE_PEEKUSER, c, (void *)dr_off(6), 0);
        long seen = ptrace(PTRACE_PEEKDATA, c, (void *)&counter, 0);
        printf("%s: stop %s dr6.b0 %ld counter %d\n", what, WSTOPSIG(st) == SIGTRAP ? "SIGTRAP" : "other",
               dr6 & 1, (int)seen);
        poke(c, 6, 0, "clear");
    } else if (WIFEXITED(st)) {
        printf("%s: exited %d\n", what, WEXITSTATUS(st));
    } else {
        printf("%s: killed by signal %d\n", what, WTERMSIG(st));
    }
}

int main(void) {
    pid_t c = fork();
    if (c < 0) { printf("fork failed\n"); return 1; }
    if (c == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGSTOP);
        counter = 1;                 /* the write watch fires here */
        int r = counter;             /* the access watch fires here */
        counter = r + 1;
        _exit(0);
    }
    int st = 0;
    waitpid(c, &st, 0);
    printf("first stop %s\n", WIFSTOPPED(st) && WSTOPSIG(st) == SIGSTOP ? "SIGSTOP" : "other");
    /* slot 0: L0 (bit 0), R/W0 at bits 16-17, LEN0 at bits 18-19 (3: four bytes) */
    poke(c, 7, 0, "off");
    poke(c, 0, (unsigned long)&counter, "place");
    poke(c, 7, 1ul | (1ul << 16) | (3ul << 18), "write-4");
    errno = 0;
    long v = ptrace(PTRACE_PEEKUSER, c, (void *)dr_off(7), 0);
    printf("peekuser dr7 %s\n", v == (long)(1ul | (1ul << 16) | (3ul << 18)) ? "as written" : "differs");
    resume_and_report(c, "write watch");
    poke(c, 7, 1ul | (3ul << 16) | (3ul << 18), "access-4");
    resume_and_report(c, "access watch");
    poke(c, 7, 0, "off");
    resume_and_report(c, "watch off");
    return 0;
}
