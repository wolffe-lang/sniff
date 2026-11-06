// SPDX-License-Identifier: GPL-3.0-or-later
#include <errno.h> // The child runs a function the debugger has a breakpoint on; the parent retries waitpid on EINTR (a traced macOS parent is interrupted by SIGCHLD).
#include <sys/wait.h>
#include <unistd.h>

int child_work(int n) {
    int tripled = n * 3;
    return tripled;
}

int main(void) {
    pid_t pid = fork();
    if (pid == 0) _exit(child_work(2));
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    int parent = child_work(1);
    return WEXITSTATUS(status) == 6 && parent == 3 ? 0 : 1;
}
