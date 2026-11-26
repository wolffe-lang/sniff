// SPDX-License-Identifier: GPL-3.0-or-later
// Where it was started: its working directory, the variable SNIFF_ROW, how many variables its environment holds and
// their names (sorted, made before main), in globals before it calls seen(), where a row stops to read them. A launch's
// cwd and env are what it finds. It prints nothing and exits 0.
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

// The environment's names, sorted and joined by spaces, made by a constructor before main runs. It is after main in
// this file so that the lines the rows stop at stay where they were.
char *names;

static int name_order(const void *a, const void *b) {
    const char *x = *(const char *const *)a, *y = *(const char *const *)b;
    while (*x && *x != '=' && *x == *y) {
        x++;
        y++;
    }
    int cx = *x == '=' ? 0 : (unsigned char)*x, cy = *y == '=' ? 0 : (unsigned char)*y;
    return cx - cy;
}

__attribute__((constructor)) static void name_them(void) {
    int n = 0, size = 1;
    for (char **e = environ; *e; e++) {
        n++;
        for (char *c = *e; *c && *c != '='; c++)
            size++;
        size++;
    }
    char **sorted = malloc((n + 1) * sizeof *sorted);
    for (int i = 0; i < n; i++)
        sorted[i] = environ[i];
    qsort(sorted, n, sizeof *sorted, name_order);
    names = malloc(size);
    char *out = names;
    for (int i = 0; i < n; i++) {
        if (i > 0)
            *out++ = ' ';
        for (char *c = sorted[i]; *c && *c != '='; c++)
            *out++ = *c;
    }
    *out = 0;
    free(sorted);
}
