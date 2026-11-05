// SPDX-License-Identifier: GPL-3.0-or-later
__attribute__((noinline)) int factorial(int n) {
    if (n <= 1) return 1;
    int smaller = factorial(n - 1);
    return n * smaller;
}
int main(void) { return factorial(5) - 120; }
