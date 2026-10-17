#include <cstdint>

#define main exception_main
#include "exceptions.cpp"
#undef main

extern "C" {
extern __thread unsigned long gsfork_control[2];
}

int main() {
    volatile intptr_t control_address = reinterpret_cast<intptr_t>(gsfork_control);
    if (control_address - reinterpret_cast<intptr_t>(__builtin_thread_pointer()) != -16)
        return 9;
    return exception_main();
}
