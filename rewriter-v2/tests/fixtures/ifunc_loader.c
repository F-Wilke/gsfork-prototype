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
    int (*direct)(int) = (int (*)(int))dlsym(library, "exported_ifunc");
    int (*caller)(int) = (int (*)(int))dlsym(library, "call_ifunc");
    int (**pointer)(int) = (int (**)(int))dlsym(library, "ifunc_pointer");
    if (!direct || !caller || !pointer || direct(13) != 42 || caller(13) != 84
        || (*pointer)(13) != 42)
        return 3;
    puts("ifunc-ok");
    return dlclose(library) ? 4 : 0;
}
