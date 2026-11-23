/* S8's calls of a kernel for a stub that must hear its client while its inferior runs, one line each
 * ("CALL -> ANSWER"), so the same static binary's output on Linux and on PAX compares line by line.
 *   (a) wait4 and waitid with WNOHANG on a traced child that runs, that stops and that exits;
 *   (b) a second thread of the tracer: wait4 (flags 0, and __WALL) for the tracee's stop, and a ptrace request;
 *   (c) SIGCHLD to a tracer blocked in poll when its tracee stops;
 *   (d) PTRACE_GETFPREGS and PTRACE_SETFPREGS of a stopped tracee;
 *   (e) PTRACE_INTERRUPT of a SEIZEd child that runs.
 * Only statuses, errnos and relations are printed, never a pid or an address. No call waits more than 3 s, and every
 * child is killed and reaped before the next part; every wait is ended by a 5 s alarm. Static; run as root on both. Sources: ptrace(2), wait(2), poll(2),
 * signal(7), pthreads(7). */
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void ms(long n) {
    struct timespec t = {n / 1000, (n % 1000) * 1000000};
    nanosleep(&t, 0);
}

static long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static void spin(long n) { /* run, not sleep: the child is running while the tracer asks */
    long end = now_ms() + n;
    volatile unsigned long x = 0;
    while (now_ms() < end) x++;
}

static const char *en(int e) {
    static char b[32];
    switch (e) {
    case EINVAL: return "EINVAL";
    case ECHILD: return "ECHILD";
    case ESRCH: return "ESRCH";
    case EIO: return "EIO";
    case EPERM: return "EPERM";
    case EINTR: return "EINTR";
    case EFAULT: return "EFAULT";
    case EAGAIN: return "EAGAIN";
    case ENOSYS: return "ENOSYS";
    }
    snprintf(b, sizeof b, "errno %d", e);
    return b;
}

static const char *sig(int s) {
    static char b[16];
    switch (s) {
    case SIGSTOP: return "SIGSTOP";
    case SIGTRAP: return "SIGTRAP";
    case SIGUSR1: return "SIGUSR1";
    case SIGKILL: return "SIGKILL";
    case SIGCHLD: return "SIGCHLD";
    }
    snprintf(b, sizeof b, "signal %d", s);
    return b;
}

static const char *status(int st) {
    static char b[64];
    if (WIFEXITED(st)) snprintf(b, sizeof b, "exited %d", WEXITSTATUS(st));
    else if (WIFSIGNALED(st)) snprintf(b, sizeof b, "killed %s", sig(WTERMSIG(st)));
    else if (WIFSTOPPED(st)) snprintf(b, sizeof b, "stopped %s%s", sig(WSTOPSIG(st)), (st >> 16) == PTRACE_EVENT_STOP ? " event-stop" : (st >> 16) ? " event" : "");
    else snprintf(b, sizeof b, "status 0x%x", st);
    return b;
}

/* a wait4 result as words: none (0), the child's status, or -1 and the errno; EINTR from a guarded wait is the 5 s
 * alarm, so the call blocked */
static const char *waited(pid_t r, pid_t c, int st, int e) {
    static char b[96];
    if (r == 0) return "0 (none)";
    if (r == c) return status(st);
    if (r < 0 && e == EINTR) return "blocked until the 5 s alarm";
    if (r < 0) { snprintf(b, sizeof b, "-1 %s", en(e)); return b; }
    return "another pid";
}

static void on_alrm(int s) { (void)s; }

/* every wait is guarded: SIGALRM (no SA_RESTART) ends it after 5 s, so a flag PAX ignores cannot hang the probe */
static pid_t wait_g(pid_t c, int *st, int flags, int *e) {
    alarm(5);
    errno = 0;
    pid_t r = waitpid(c, st, flags);
    *e = errno;
    alarm(0);
    return r;
}

static void line(const char *call, const char *answer) {
    printf("%s -> %s\n", call, answer);
    fflush(stdout);
}

/* a traced child: TRACEME, its own SIGSTOP, then it runs for RUN ms, raises SIGUSR1 (a signal-delivery stop for the
 * tracer), runs again and exits with CODE */
static pid_t traced_child(long run, int code) {
    pid_t c = fork();
    if (c == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGSTOP);
        spin(run);
        raise(SIGUSR1);
        spin(run);
        _exit(code);
    }
    return c;
}

static void finish(pid_t c) { /* every child killed and reaped */
    int st, e;
    kill(c, SIGKILL);
    while (wait_g(c, &st, __WALL, &e) == c && !WIFEXITED(st) && !WIFSIGNALED(st)) {
    }
}

/* poll wait4(WNOHANG) every 10 ms for at most 3 s */
static pid_t poll_wait(pid_t c, int *st, int *e) {
    pid_t r = 0;
    for (int n = 0; n < 300; n++) {
        r = wait_g(c, st, WNOHANG, e);
        if (r != 0) break;
        ms(10);
    }
    return r;
}

static void part_a(void) {
    int st = 0, e;
    pid_t c = traced_child(300, 7), r;
    r = wait_g(c, &st, 0, &e);
    line("a: wait4 0 for TRACEME's own stop", waited(r, c, st, e));
    errno = 0;
    line("a: PTRACE_CONT of the stopped child", ptrace(PTRACE_CONT, c, 0, 0) == 0 ? "0" : en(errno));
    r = wait_g(c, &st, WNOHANG, &e);
    line("a: wait4 WNOHANG at once, while the traced child runs", waited(r, c, st, e));
    siginfo_t si;
    memset(&si, 0, sizeof si);
    alarm(5);
    errno = 0;
    int w = waitid(P_PID, c, &si, WEXITED | WSTOPPED | WNOHANG);
    e = errno;
    alarm(0);
    line("a: waitid WEXITED|WSTOPPED|WNOHANG while it runs",
         w == 0 ? (si.si_pid == 0 ? "0, si_pid 0 (none)" : "0, a child's state") : e == EINTR ? "blocked until the 5 s alarm" : en(e));
    r = poll_wait(c, &st, &e);
    line("a: wait4 WNOHANG every 10 ms until it stops", r == 0 ? "never within 3 s" : waited(r, c, st, e));
    if (r == c && WIFSTOPPED(st)) {
        errno = 0;
        line("a: PTRACE_CONT suppressing SIGUSR1", ptrace(PTRACE_CONT, c, 0, 0) == 0 ? "0" : en(errno));
        r = poll_wait(c, &st, &e);
        line("a: wait4 WNOHANG every 10 ms until it exits", r == 0 ? "never within 3 s" : waited(r, c, st, e));
        if (r == c && (WIFEXITED(st) || WIFSIGNALED(st))) {
            r = wait_g(c, &st, WNOHANG, &e);
            line("a: wait4 WNOHANG once it is reaped", waited(r, c, st, e));
            return;
        }
    }
    finish(c);
}

struct helper {
    pid_t child;
    int flags;
    volatile int done;
    pid_t r;
    int st, e, peek_e;
    long peek;
};

static void *helper_main(void *p) {
    struct helper *h = p;
    errno = 0;
    h->r = waitpid(h->child, &h->st, h->flags);
    h->e = errno;
    errno = 0;
    h->peek = ptrace(PTRACE_PEEKUSER, h->child, 0, 0);
    h->peek_e = errno;
    h->done = 1;
    return 0;
}

static void part_b(int flags, const char *name) {
    char call[128];
    int st = 0, e;
    pid_t c = traced_child(300, 9), r;
    r = wait_g(c, &st, 0, &e);
    snprintf(call, sizeof call, "b%s: wait4 0 for TRACEME's own stop", name);
    line(call, waited(r, c, st, e));
    ptrace(PTRACE_CONT, c, 0, 0);
    struct helper h = {c, flags, 0, 0, 0, 0, 0, 0};
    pthread_t t;
    pthread_create(&t, 0, helper_main, &h);
    for (int n = 0; n < 300 && !h.done; n++) ms(10);
    snprintf(call, sizeof call, "b%s: a second thread's wait4 for the tracee's stop", name);
    if (!h.done) {
        line(call, "blocked 3 s");
        r = wait_g(c, &st, __WALL, &e);
        snprintf(call, sizeof call, "b%s: then the tracer thread's wait4 __WALL", name);
        line(call, waited(r, c, st, e));
        finish(c);
        pthread_join(t, 0);
        snprintf(call, sizeof call, "b%s: the second thread's wait4 once the child is reaped", name);
        line(call, waited(h.r, c, h.st, h.e));
        return;
    }
    pthread_join(t, 0);
    line(call, waited(h.r, c, h.st, h.e));
    snprintf(call, sizeof call, "b%s: the second thread's PTRACE_PEEKUSER of the stopped tracee", name);
    line(call, h.peek_e == 0 ? "a word" : en(h.peek_e));
    errno = 0;
    long v = ptrace(PTRACE_PEEKUSER, c, 0, 0);
    snprintf(call, sizeof call, "b%s: the tracer thread's PTRACE_PEEKUSER of it", name);
    line(call, errno == 0 ? "a word" : en(errno));
    (void)v;
    finish(c);
}

static volatile sig_atomic_t chld;
static void on_chld(int s) { (void)s; chld++; }

static void part_c(void) {
    int p[2], st = 0, e;
    if (pipe(p) != 0) { line("c: pipe", en(errno)); return; }
    pid_t c = traced_child(300, 5), r;
    r = wait_g(c, &st, 0, &e);
    line("c: wait4 0 for TRACEME's own stop", waited(r, c, st, e));
    struct sigaction sa; /* installed once the first stop is collected */
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_chld; /* no SA_RESTART: poll ends with EINTR */
    sigaction(SIGCHLD, &sa, 0);
    chld = 0;
    ptrace(PTRACE_CONT, c, 0, 0);
    struct pollfd f = {p[0], POLLIN, 0};
    long t0 = now_ms();
    errno = 0;
    int n = poll(&f, 1, 3000);
    e = errno;
    long dt = now_ms() - t0;
    char b[96];
    snprintf(b, sizeof b, "%s, SIGCHLD %s, %s", n < 0 ? en(e) : n == 0 ? "0 (timeout)" : "ready",
             chld ? "seen" : "not seen", dt < 2500 ? "before 2.5 s" : "after 2.5 s");
    line("c: poll of an empty pipe for 3 s while the tracee runs to its SIGUSR1 stop", b);
    r = wait_g(c, &st, WNOHANG, &e);
    line("c: then wait4 WNOHANG", waited(r, c, st, e));
    finish(c);
    signal(SIGCHLD, SIG_DFL);
    close(p[0]);
    close(p[1]);
}

static void part_d(void) {
    int st = 0, e;
    pid_t c = traced_child(300, 3), r;
    r = wait_g(c, &st, 0, &e);
    line("d: wait4 0 for TRACEME's own stop", waited(r, c, st, e));
    struct user_fpregs_struct fp;
    memset(&fp, 0, sizeof fp);
    errno = 0;
    line("d: PTRACE_GETFPREGS", ptrace(PTRACE_GETFPREGS, c, 0, &fp) == 0 ? "0" : en(errno));
    errno = 0;
    line("d: PTRACE_SETFPREGS of what GETFPREGS gave", ptrace(PTRACE_SETFPREGS, c, 0, &fp) == 0 ? "0" : en(errno));
    finish(c);
}

static void part_e(void) {
    int st = 0, e;
    pid_t c = fork(), r;
    if (c == 0) {
        spin(3000);
        _exit(0);
    }
    ms(50);
    errno = 0;
    line("e: PTRACE_SEIZE of a running child", ptrace(PTRACE_SEIZE, c, 0, 0) == 0 ? "0" : en(errno));
    errno = 0;
    line("e: PTRACE_INTERRUPT of it, running", ptrace(PTRACE_INTERRUPT, c, 0, 0) == 0 ? "0" : en(errno));
    r = wait_g(c, &st, __WALL, &e);
    line("e: wait4 __WALL after the interrupt", waited(r, c, st, e));
    finish(c);
}

int main(void) {
    setvbuf(stdout, 0, _IONBF, 0);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_alrm; /* no SA_RESTART: a guarded wait ends with EINTR */
    sigaction(SIGALRM, &sa, 0);
    part_a();
    part_b(0, "0");
    part_b(__WALL, "-wall");
    part_c();
    part_d();
    part_e();
    line("done", "ok");
    return 0;
}
