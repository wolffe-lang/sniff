// SPDX-License-Identifier: GPL-3.0-or-later
// Base types, pointers and returned values for print, info, x and finish.
#include <stdbool.h>

char letter(char c) { char next = c + 1; return next; }
unsigned char low_byte(unsigned value) { unsigned char low = value & 0xff; return low; }
short narrow(short s) { short twice = s * 2; return twice; }
long widen(int v) { long w = v; return w * 1000000000L; }
unsigned long all_ones(void) { unsigned long m = 0; return m - 1; }
float third(float f) { float t = f / 3; return t; }
double tenth(double d) { double t = d / 10; return t; }
bool positive(int v) { bool p = v > 0; return p; }
int *address_of(int *p) { int *q = p; return q; }

int inspect(char c, short s, int i, long l, unsigned u, unsigned long ul,
            float f, double d, bool b, int *p) {
    int sum = c + s + i + (int)l + (int)u + (int)ul;
    double scaled = d * f;
    int flag = b ? *p : 0;
    return sum + flag + (int)scaled;
}

int main(void) {
    int cell = -7;
    int words[4] = {1, 2, 3, 4};
    char a = letter('A');
    unsigned char lo = low_byte(0x1234);
    short n = narrow(-300);
    long w = widen(7);
    unsigned long m = all_ones();
    float t = third(1.0f);
    double x = tenth(1.0);
    bool ok = positive(5);
    int *q = address_of(&cell);
    int r = inspect('z', -2, 3, -4000000000L, 5u, 6ul, 0.5f, 0.1, true, q);
    return (a + lo + n + (int)w + (int)m + (int)t + (int)x + ok + r + words[0]) & 0;
}
