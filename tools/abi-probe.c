/* SPDX-License-Identifier: GPL-3.0-or-later */
/* R-sn02-3: print the ptrace request numbers, the user_regs_struct layout
 * and the wait-status truth table by compiling against the C library and
 * running, so no header text is read. Output is committed as
 * tests/evidence/linux-s2/abi.txt and checked by tools/check-abi.py. */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/personality.h>
#include <sys/resource.h>
#include <sys/user.h>
#include <sys/wait.h>

#define REQ(n) printf("request %s %d\n", #n, (int)(n))
#define OFF(f) printf("regs %s %d\n", #f, (int)(offsetof(struct user_regs_struct, f) / 8))

static void status(const char *name, int code, int sig) {
    pid_t p = fork();
    if (p == 0) {
        if (sig) { signal(sig, SIG_DFL); raise(sig); }
        _exit(code);
    }
    int st = 0;
    waitpid(p, &st, 0);
    /* the core-dump flag (bit 7) depends on core_pattern and limits, so it is cleared from the record */
    printf("wait %s raw=%d exited=%d exitstatus=%d signaled=%d termsig=%d\n", name, st & ~0x80,
           WIFEXITED(st) ? 1 : 0, WIFEXITED(st) ? WEXITSTATUS(st) : -1, WIFSIGNALED(st) ? 1 : 0,
           WIFSIGNALED(st) ? WTERMSIG(st) : -1);
}

int main(void) {
    /* no core files: the raw status of SIGSEGV must not depend on ulimit -c */
    struct rlimit nocore = {0, 0};
    setrlimit(RLIMIT_CORE, &nocore);
    REQ(PTRACE_TRACEME); REQ(PTRACE_PEEKTEXT); REQ(PTRACE_PEEKDATA); REQ(PTRACE_PEEKUSER);
    REQ(PTRACE_POKETEXT); REQ(PTRACE_POKEDATA); REQ(PTRACE_POKEUSER); REQ(PTRACE_CONT);
    REQ(PTRACE_KILL); REQ(PTRACE_SINGLESTEP); REQ(PTRACE_GETREGS); REQ(PTRACE_SETREGS);
    REQ(PTRACE_SETOPTIONS); REQ(PTRACE_O_EXITKILL); REQ(PTRACE_GETFPREGS); REQ(PTRACE_DETACH);
    REQ(PTRACE_GETEVENTMSG); REQ(PTRACE_O_TRACEFORK); REQ(PTRACE_O_TRACEVFORK);
    printf("request ADDR_NO_RANDOMIZE %d\n", (int)ADDR_NO_RANDOMIZE);
    printf("regs size %d\n", (int)(sizeof(struct user_regs_struct) / 8));
    OFF(r15); OFF(r14); OFF(r13); OFF(r12); OFF(rbp); OFF(rbx); OFF(r11); OFF(r10); OFF(r9); OFF(r8);
    OFF(rax); OFF(rcx); OFF(rdx); OFF(rsi); OFF(rdi); OFF(orig_rax); OFF(rip); OFF(cs); OFF(eflags);
    OFF(rsp); OFF(ss); OFF(fs_base); OFF(gs_base); OFF(ds); OFF(es); OFF(fs); OFF(gs);
    /* S5: the debug registers, read and written with PEEKUSER and POKEUSER at these byte offsets */
    printf("user u_debugreg %d\n", (int)offsetof(struct user, u_debugreg));
    printf("user u_debugreg_size %d\n", (int)sizeof(((struct user *)0)->u_debugreg[0]));
    status("exit0", 0, 0); status("exit3", 3, 0); status("exit255", 255, 0);
    status("sigsegv", 0, SIGSEGV); status("sigkill", 0, SIGKILL); status("sigabrt", 0, SIGABRT);
    /* the stop at exec: PTRACE_TRACEME, then exec; first stop status */
    pid_t p = fork();
    if (p == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        personality(ADDR_NO_RANDOMIZE);
        execl("/bin/true", "true", (char *)0);
        _exit(127);
    }
    int st = 0;
    waitpid(p, &st, 0);
    printf("wait exec-stop raw=%d stopped=%d stopsig=%d\n", st, WIFSTOPPED(st) ? 1 : 0, WIFSTOPPED(st) ? WSTOPSIG(st) : -1);
    ptrace(PTRACE_KILL, p, 0, 0);
    waitpid(p, &st, 0);
    return 0;
}
