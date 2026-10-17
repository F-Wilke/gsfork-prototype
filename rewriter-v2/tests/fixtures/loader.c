#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc != 2)
        return 1;
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) {
        fprintf(stderr, "%s\n", dlerror());
        return 2;
    }
    int (*function)(void) = (int (*)(void))dlvsym(library, "gs_shared", "GS_1.0");
    if (!function || function() != 42)
        return 3;
    return dlclose(library) ? 4 : 0;
}
