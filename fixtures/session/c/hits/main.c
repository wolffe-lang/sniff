// SPDX-License-Identifier: GPL-3.0-or-later
// A breakpoint target crossed 10,000 times.
int tick(int n) {
    return n + 1;
}

int main(void) {
    int n = 0;
    for (int i = 0; i < 10000; i++) {
        n = tick(n);
    }
    return n == 10000 ? 0 : 1;
}
