// SPDX-License-Identifier: GPL-3.0-or-later
// Stepping: recursion, a callee without line info, loops for until.
int plain_twice(int v);

int depth_sum(int n) {
    if (n == 0) return 0;
    int below = depth_sum(n - 1);
    return n + below;
}

int count(int limit) {
    int total = 0;
    for (int i = 0; i < limit; i++) {
        total += i;
    }
    return total;
}

int main(void) {
    int a = plain_twice(4);
    int b = depth_sum(3);
    int c = count(5);
    return a + b + c - 24;
}
