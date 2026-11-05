// SPDX-License-Identifier: GPL-3.0-or-later
__attribute__((noinline)) int deref(const int *p) {
    const int *q = p;
    return *q + 1;
}
int main(void) {
    int value = 6;
    int *pointer = &value;
    return deref(pointer) - 7;
}
