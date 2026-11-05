// SPDX-License-Identifier: GPL-3.0-or-later
struct Point { int x; long y; };
__attribute__((noinline)) long total(struct Point p) {
    long sum = p.x + p.y;
    return sum;
}
int main(void) {
    struct Point p = {3, 4};
    return (int)total(p) - 7;
}
