/* A call back through the C library: qsort calls order(), so a stop in order() has the library's own frames
 * between it and main. In a dynamic program those frames are unwound by the library's .eh_frame and named
 * from its dynamic symbols, or `?? () from LIB` where none covers the pc. */
#include <stdlib.h>

static int calls;

int order(const void *a, const void *b) {
    int x = *(const int *)a, y = *(const int *)b;
    calls++;
    return (x > y) - (x < y);
}

int main(void) {
    int v[] = {3, 1, 2};
    qsort(v, 3, sizeof v[0], order);
    return v[0] == 1 && v[1] == 2 && v[2] == 3 && calls > 0 ? 0 : 1;
}
