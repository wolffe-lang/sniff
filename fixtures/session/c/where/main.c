// SPDX-License-Identifier: GPL-3.0-or-later
// Where it was started: its working directory, the variable SNIFF_ROW, and how many variables its environment holds,
// read into globals before it calls seen(), where a row stops to read them. A launch's cwd and env are what it finds.
// It prints nothing and exits 0.
#include <stdlib.h>
#include <unistd.h>

extern char **environ;

char *where;
char *row;
int envc;

void seen(void) {
}

int main(void) {
    where = getcwd(NULL, 0);
    row = getenv("SNIFF_ROW");
    for (char **e = environ; *e; e++)
        envc++;
    seen();
    return 0;
}
