#define _GNU_SOURCE
#include <dlfcn.h>

int main(int argc, char **argv) {
    if (argc != 2)
        return 1;
    void *handle = dlopen(argv[1], RTLD_NOW);
    if (!handle)
        return 2;
    int (*old)(void) = (int (*)(void))dlvsym(handle, "version_api", "VERS_1");
    int (*current)(void) = (int (*)(void))dlsym(handle, "version_api");
    int (*both)(void) = (int (*)(void))dlsym(handle, "call_versions");
    if (!old || !current || !both || old() != 13 || current() != 29 || both() != 1329)
        return 3;
    return dlclose(handle) ? 4 : 0;
}
