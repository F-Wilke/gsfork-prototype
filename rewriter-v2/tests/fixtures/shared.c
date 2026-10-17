#include <stdio.h>

static int state;

__attribute__((constructor)) static void initialize(void) {
    state = 19;
}

__attribute__((destructor)) static void finalize(void) {
    puts(state == 42 ? "shared-fini-ok" : "shared-fini-bad");
}

int gs_shared(void) {
    if (state != 19)
        return -1;
    state = 42;
    return state;
}
