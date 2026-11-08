// SPDX-License-Identifier: GPL-3.0-or-later
// A tracer that holds another process: PTRACE_SEIZE of PID (which does not stop it), "held PID" on
// standard output, a wait of MS milliseconds, then its exit, which detaches the process (ptrace(2)).
// While it holds the process, a debugger's attach to it is refused, as ptrace(2) refuses a second
// tracer. Linux and PAX only.
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#if defined(__linux__)
#include <sys/ptrace.h>
#endif

int main(int argc, char **argv) {
    if (argc < 3) return 2;
#if defined(__linux__)
    long pid = atol(argv[1]);
    long ms = atol(argv[2]);
    if (ptrace(PTRACE_SEIZE, pid, 0, 0) != 0) {
        perror("seize");
        return 1;
    }
    printf("held %ld\n", pid);
    fflush(stdout);
    struct timespec ts = {ms / 1000, (ms % 1000) * 1000000};
    nanosleep(&ts, 0);
    return 0;
#else
    return 3;
#endif
}
