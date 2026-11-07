/* The calls sniff's later milestones ask of a kernel, each answered in one line: "CALL result".
 * Static, no -g needed. Run the same binary on Linux and on PAX and compare the lines. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static void readfile(const char *label, const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { printf("open %s -> -1 errno %d\n", label, errno); return; }
    char buf[4096];
    ssize_t n = read(fd, buf, sizeof buf - 1);
    printf("open+read %s -> %zd bytes\n", label, n);
    close(fd);
}

int main(int argc, char **argv) {
    char path[128];
    long pid = getpid();
    readfile("/proc/self/maps", "/proc/self/maps");
    readfile("/proc/self/auxv", "/proc/self/auxv");
    readfile("/proc/self/status", "/proc/self/status");
    snprintf(path, sizeof path, "/proc/%ld/task/%ld/stat", pid, pid);
    readfile("task/TID/stat", path);
    readfile("/proc/self/stat", "/proc/self/stat");
    errno = 0;
    int p = personality(0xffffffff);
    printf("personality(query) -> %s\n", p == -1 ? "-1" : "ok");
    errno = 0;
    p = personality(ADDR_NO_RANDOMIZE);
    printf("personality(ADDR_NO_RANDOMIZE) -> %s errno %d\n", p == -1 ? "-1" : "ok", p == -1 ? errno : 0);
    /* fork with a resident set of N MiB: PAX copies the address space (no copy-on-write) */
    size_t mib = argc > 1 ? (size_t)atoi(argv[1]) : 64;
    char *big = malloc(mib << 20);
    if (big) memset(big, 1, mib << 20);
    pid_t c = fork();
    if (c == 0) _exit(0);
    int st = 0;
    if (c > 0) waitpid(c, &st, 0);
    printf("fork with %zu MiB resident -> %s\n", mib, c < 0 ? "failed" : (WIFEXITED(st) ? "child exited 0" : "child odd"));
    return 0;
}
