#include <pthread.h>
#include <stdio.h>

__thread int exported_tls = 233;
static __thread long private_tls = 17;
static __thread char zero_tls[24];

static void *worker(void *argument) {
    int id = *(int *)argument;
    if (exported_tls != 233 || private_tls != 17 || zero_tls[23])
        return argument;
    exported_tls = id * 10;
    private_tls = id;
    zero_tls[23] = (char)id;
    if (exported_tls != id * 10 || private_tls != id || zero_tls[23] != id)
        return argument;
    return NULL;
}

int main(void) {
    pthread_t threads[5];
    int ids[5];
    for (int i = 0; i < 5; ++i) {
        ids[i] = i + 1;
        if (pthread_create(&threads[i], NULL, worker, &ids[i]))
            return 2;
    }
    for (int i = 0; i < 5; ++i) {
        void *result;
        if (pthread_join(threads[i], &result) || result)
            return 3;
    }
    if (exported_tls != 233 || private_tls != 17 || zero_tls[23])
        return 4;
    puts("local-exec-tls-ok");
    return 0;
}
