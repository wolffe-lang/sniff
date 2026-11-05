// SPDX-License-Identifier: GPL-3.0-or-later
#include <pthread.h>
static int result;
static void *worker(void *arg) {
    int *value = arg;
    result = *value + 1;
    return 0;
}
int main(void) {
    pthread_t thread;
    int value = 6;
    if (pthread_create(&thread, 0, worker, &value)) return 2;
    if (pthread_join(thread, 0)) return 3;
    return result - 7;
}
