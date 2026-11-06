// SPDX-License-Identifier: GPL-3.0-or-later
// Exit paths chosen by argv: 0, a code, exit() from a callee, a fault.
#include <stdlib.h>
#include <string.h>

int code(const char *text) {
    int value = atoi(text);
    return value;
}

void leave(const char *text) {
    int value = code(text);
    exit(value);
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "fault") == 0) {
        volatile int *nowhere = 0;
        *nowhere = 1;
    }
    if (argc > 2) leave(argv[2]);
    if (argc > 1) return code(argv[1]);
    return 0;
}
