// SPDX-License-Identifier: GPL-3.0-or-later
static inline __attribute__((always_inline)) int twice(int n) {
    int doubled = n * 2;
    return doubled;
}
__attribute__((noinline)) int caller(int n) { return twice(n) + 1; }
int main(int argc, char **argv) {
    (void)argv;
    return caller(argc + 2) - 7;
}
