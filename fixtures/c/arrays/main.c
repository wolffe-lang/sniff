// SPDX-License-Identifier: GPL-3.0-or-later
__attribute__((noinline)) int sum(const int *a, int n) {
    int total = 0;
    for (int i = 0; i < n; i++) total += a[i];
    return total;
}
int main(void) {
    int items[4] = {1, 2, 3, 4};
    return sum(items, 4) - 10;
}
