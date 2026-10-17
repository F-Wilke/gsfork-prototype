#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>

static int (*value)(void);
static void (*change)(void);

static void *thread(void *unused) {
    (void)unused;
    if (value() != 42)
        return (void *)1;
    change();
    return value() == 45 ? NULL : (void *)1;
}

int main(int argc, char **argv) {
    if (argc != 2)
        return 1;
    void *handle = dlopen(argv[1], RTLD_NOW);
    if (!handle)
        return 2;
    value = (int (*)(void))dlsym(handle, "tls_value");
    change = (void (*)(void))dlsym(handle, "tls_change");
    if (!value || !change || value() != 42)
        return 3;
    change();
    if (value() != 45)
        return 4;
    pthread_t tid;
    void *result;
    if (pthread_create(&tid, NULL, thread, NULL) || pthread_join(tid, &result) || result || value() != 45)
        return 5;
    puts("tls-thread-ok");
    return dlclose(handle) ? 6 : 0;
}
