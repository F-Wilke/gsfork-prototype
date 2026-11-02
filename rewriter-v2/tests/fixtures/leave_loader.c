#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern long invoke_parent_leave(void *function, intptr_t delta);

int main(int argc, char **argv) {
    if (argc != 3)
        return 2;
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) {
        fprintf(stderr, "%s\n", dlerror());
        return 3;
    }
    void *function = dlsym(library, "parent_frame_exit");
    if (!function || invoke_parent_leave(function, strtol(argv[2], NULL, 0)))
        return 4;
    if (dlclose(library))
        return 5;
    puts("parent-leave-ok");
    return 0;
}
