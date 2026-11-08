/* S6's calls of a kernel, one line each ("CALL -> ANSWER"), so the same static binary's output on Linux and
 * on PAX compares line by line. Threads: PTRACE_O_TRACECLONE, a new thread's first stop, tgkill of one
 * thread, per-thread registers, /proc/PID/task. Signals: signal-delivery stops, PTRACE_GETSIGINFO,
 * injection, suppression and replacement, a fault. Attach: ATTACH of a process the prober did not start,
 * the refusals, DETACH, SEIZE and INTERRUPT. Only statuses, errnos and relations are printed, never a pid
 * or an address. Static; run as root on both. Sources: ptrace(2), wait(2), proc(5), tgkill(2). */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void ms(long n) {
    struct timespec t = {n / 1000, (n % 1000) * 1000000};
    nanosleep(&t, 0);
}

static int wait_for(pid_t pid) {
    int st = 0;
    if (waitpid(pid, &st, __WALL) != pid) return -1;
    return st;
}

static void say_call(const char *what, long r) {
    if (r == -1) printf("%s -> -1 errno %d\n", what, errno);
    else printf("%s -> %ld\n", what, r);
}

static void readfirst(const char *label, const char *path, int field) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { printf("%s -> open -1 errno %d\n", label, errno); return; }
    char buf[4096];
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n < 0) { printf("%s -> read -1 errno %d\n", label, errno); return; }
    buf[n] = 0;
    if (field == 0) {
        char *nl = strchr(buf, '\n');
        if (nl) *nl = 0;
        printf("%s -> \"%s\"\n", label, buf);
        return;
    }
    /* stat: the state is the field after the parenthesised name */
    char *close_paren = strrchr(buf, ')');
    printf("%s -> state %c\n", label, close_paren && close_paren[1] == ' ' ? close_paren[2] : '?');
}

/* ---- threads ---- */

static volatile long second_self;
static volatile int second_go;

static void *second(void *arg) {
    second_self = (long)pthread_self();
    while (!second_go) ms(1);
    return 0;
}

static int threaded_child(void) {
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    raise(SIGSTOP);
    pthread_t t;
    if (pthread_create(&t, 0, second, 0)) return 2;
    pthread_join(t, 0);
    return 7;
}

static void threads(void) {
    char path[128];
    pid_t pid = fork();
    if (pid == 0) _exit(threaded_child());
    printf("threads: traceme stop -> 0x%x\n", wait_for(pid));
    say_call("threads: SETOPTIONS TRACECLONE|EXITKILL",
             ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACECLONE | PTRACE_O_EXITKILL));
    ptrace(PTRACE_CONT, pid, 0, 0);
    printf("threads: clone event stop -> 0x%x\n", wait_for(pid));
    unsigned long msg = 0;
    say_call("threads: GETEVENTMSG", ptrace(PTRACE_GETEVENTMSG, pid, 0, &msg));
    pid_t tid = (pid_t)msg;
    printf("threads: event message is a new thread id -> %s\n", tid > 0 && tid != pid ? "yes" : "no");
    printf("threads: the new thread's first stop -> 0x%x\n", wait_for(tid));
    snprintf(path, sizeof path, "/proc/%d/task", pid);
    DIR *d = opendir(path);
    if (!d) printf("threads: /proc/PID/task -> opendir errno %d\n", errno);
    else {
        int n = 0;
        struct dirent *e;
        while ((e = readdir(d))) if (e->d_name[0] != '.') n++;
        closedir(d);
        printf("threads: /proc/PID/task entries -> %d\n", n);
    }
    snprintf(path, sizeof path, "/proc/%d/task/%d/comm", pid, tid);
    readfirst("threads: task/TID/comm", path, 0);
    snprintf(path, sizeof path, "/proc/%d/task/%d/stat", pid, tid);
    readfirst("threads: task/TID/stat", path, 1);
    snprintf(path, sizeof path, "/proc/%d/comm", pid);
    readfirst("threads: /proc/PID/comm", path, 0);
    /* let the thread run, then stop it alone: tgkill(2) */
    ptrace(PTRACE_CONT, tid, 0, 0);
    ptrace(PTRACE_CONT, pid, 0, 0);
    ms(100);
    say_call("threads: tgkill SIGSTOP the thread", syscall(SYS_tgkill, pid, tid, SIGSTOP));
    printf("threads: the thread's stop -> 0x%x\n", wait_for(tid));
    say_call("threads: tgkill SIGSTOP the leader", syscall(SYS_tgkill, pid, pid, SIGSTOP));
    printf("threads: the leader's stop -> 0x%x\n", wait_for(pid));
    struct user_regs_struct rt, rl;
    say_call("threads: GETREGS of the thread", ptrace(PTRACE_GETREGS, tid, 0, &rt));
    say_call("threads: GETREGS of the leader", ptrace(PTRACE_GETREGS, pid, 0, &rl));
    errno = 0;
    long self = ptrace(PTRACE_PEEKDATA, pid, (void *)&second_self, 0);
    printf("threads: the thread's fs_base is its pthread_self -> %s\n", errno == 0 && (long)rt.fs_base == self ? "yes" : "no");
    printf("threads: the two threads' stacks differ -> %s\n", rt.rsp != rl.rsp ? "yes" : "no");
    errno = 0;
    long viatid = ptrace(PTRACE_PEEKDATA, tid, (void *)&second_self, 0);
    printf("threads: PEEKDATA through the thread's id -> %s\n", errno == 0 && viatid == self ? "same word" : "differs");
    say_call("threads: POKEDATA the thread's flag", ptrace(PTRACE_POKEDATA, pid, (void *)&second_go, (void *)1));
    ptrace(PTRACE_CONT, tid, 0, 0);
    ptrace(PTRACE_CONT, pid, 0, 0);
    int st = wait_for(tid);
    printf("threads: the thread's end -> exited %s status 0x%x\n", WIFEXITED(st) ? "yes" : "no", st);
    st = wait_for(pid);
    printf("threads: the leader's end -> exited %s code %d\n", WIFEXITED(st) ? "yes" : "no", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
}

/* ---- signals ---- */

static volatile sig_atomic_t usr1, usr2;
static void on_usr1(int s) { usr1++; }
static void on_usr2(int s) { usr2++; }

static void signals(void) {
    pid_t pid = fork();
    if (pid == 0) {
        signal(SIGUSR1, on_usr1);
        signal(SIGUSR2, on_usr2);
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGSTOP);
        kill(getpid(), SIGUSR1);
        kill(getpid(), SIGUSR1);
        kill(getpid(), SIGUSR1);
        _exit(usr1 * 10 + usr2);
    }
    printf("signals: traceme stop -> 0x%x\n", wait_for(pid));
    ptrace(PTRACE_CONT, pid, 0, 0);
    printf("signals: SIGUSR1 delivery stop -> 0x%x\n", wait_for(pid));
    siginfo_t si;
    memset(&si, 0, sizeof si);
    say_call("signals: GETSIGINFO", ptrace(PTRACE_GETSIGINFO, pid, 0, &si));
    printf("signals: siginfo -> signo %d code %d sender is the tracee %s\n", si.si_signo, si.si_code, si.si_pid == pid ? "yes" : "no");
    ptrace(PTRACE_CONT, pid, 0, SIGUSR1);
    printf("signals: passed, the second stop -> 0x%x\n", wait_for(pid));
    ptrace(PTRACE_CONT, pid, 0, 0);
    printf("signals: suppressed, the third stop -> 0x%x\n", wait_for(pid));
    ptrace(PTRACE_CONT, pid, 0, SIGUSR2);
    int st = wait_for(pid);
    printf("signals: replaced by SIGUSR2, the end -> code %d (usr1 1 and usr2 1 make 11)\n", WIFEXITED(st) ? WEXITSTATUS(st) : -1);

    pid = fork();
    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGSTOP);
        *(volatile int *)0 = 1;
        _exit(0);
    }
    wait_for(pid);
    ptrace(PTRACE_CONT, pid, 0, 0);
    printf("signals: a fault's stop -> 0x%x\n", wait_for(pid));
    memset(&si, 0, sizeof si);
    ptrace(PTRACE_GETSIGINFO, pid, 0, &si);
    printf("signals: the fault's siginfo -> signo %d code %d address zero %s\n", si.si_signo, si.si_code, si.si_addr == 0 ? "yes" : "no");
    ptrace(PTRACE_CONT, pid, 0, 0);
    printf("signals: the fault suppressed, it faults again -> 0x%x\n", wait_for(pid));
    ptrace(PTRACE_CONT, pid, 0, SIGSEGV);
    st = wait_for(pid);
    printf("signals: the fault passed, the end -> signaled %s signal %d\n", WIFSIGNALED(st) ? "yes" : "no", WIFSIGNALED(st) ? WTERMSIG(st) : -1);
}

/* ---- attach ---- */

static pid_t sleeper(int ticks) {
    pid_t pid = fork();
    if (pid == 0) {
        for (int i = 0; i < ticks; i++) ms(10);
        _exit(0);
    }
    return pid;
}

static void attach(void) {
    pid_t s = sleeper(150);
    ms(50);
    pid_t a = fork();
    if (a == 0) {
        /* a sibling: the sleeper is not this process's child */
        say_call("attach: ATTACH a sibling", ptrace(PTRACE_ATTACH, s, 0, 0));
        printf("attach: the attach stop -> 0x%x\n", wait_for(s));
        struct user_regs_struct r;
        say_call("attach: GETREGS", ptrace(PTRACE_GETREGS, s, 0, &r));
        say_call("attach: ATTACH it a second time", ptrace(PTRACE_ATTACH, s, 0, 0));
        say_call("attach: DETACH", ptrace(PTRACE_DETACH, s, 0, 0));
        fflush(stdout);
        _exit(0);
    }
    wait_for(a);
    int st = wait_for(s);
    printf("attach: the sleeper after the detach -> exited %s code %d\n", WIFEXITED(st) ? "yes" : "no", WIFEXITED(st) ? WEXITSTATUS(st) : -1);

    s = sleeper(150);
    ms(50);
    pid_t h = fork();
    if (h == 0) {
        /* a holder: another tracer has the sleeper */
        ptrace(PTRACE_SEIZE, s, 0, 0);
        ms(400);
        _exit(0);
    }
    ms(100);
    say_call("attach: ATTACH a process another tracer holds", ptrace(PTRACE_ATTACH, s, 0, 0));
    wait_for(h);
    wait_for(s);

    say_call("attach: ATTACH no such process", ptrace(PTRACE_ATTACH, 4000000, 0, 0));
    say_call("attach: ATTACH itself", ptrace(PTRACE_ATTACH, getpid(), 0, 0));

    s = sleeper(150);
    ms(50);
    say_call("attach: SEIZE", ptrace(PTRACE_SEIZE, s, 0, 0));
    say_call("attach: INTERRUPT", ptrace(PTRACE_INTERRUPT, s, 0, 0));
    printf("attach: the interrupt stop -> 0x%x\n", wait_for(s));
    say_call("attach: DETACH", ptrace(PTRACE_DETACH, s, 0, 0));
    st = wait_for(s);
    printf("attach: the seized sleeper after the detach -> exited %s code %d\n", WIFEXITED(st) ? "yes" : "no", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
}

int main(void) {
    setvbuf(stdout, 0, _IONBF, 0);
    threads();
    signals();
    attach();
    printf("probe: end\n");
    return 0;
}
