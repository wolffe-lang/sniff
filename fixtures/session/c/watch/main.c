// SPDX-License-Identifier: GPL-3.0-or-later
// Watchpoints and expressions: a global written, read and rewritten with its own value,
// a struct with an array member reached directly and through a pointer, and a local in a
// loop whose frame returns.
struct point {
    int x;
    int y;
    int hist[4];
};

int counter = 0;
struct point origin = {1, 2, {10, 20, 30, 40}};
struct point *cursor = &origin;
double scale = 1.5;

int bump(int by) {
    counter += by;
    return counter;
}

int peek(void) {
    int seen = counter;
    return seen + 1;
}

int walk(int n) {
    int total = 0;
    for (int i = 0; i < n; i++) {
        total += i;
    }
    return total;
}

int main(void) {
    bump(3);
    origin.hist[2] = 31;
    cursor->y = 5;
    counter = counter;
    int seen = peek();
    int sum = walk(4);
    origin.x = sum + seen;
    bump(1);
    return 0;
}
