#include <execinfo.h>
#include <cstdio>
#include <stdexcept>

static int state;
struct Lifetime {
    Lifetime() { state = 7; }
    ~Lifetime() { std::puts(state == 19 ? "fini-ok" : "fini-bad"); }
} lifetime;

struct Cleanup {
    ~Cleanup() { state += 5; }
};

__attribute__((noinline)) static void raise_error() {
    Cleanup cleanup;
    void *frames[32];
    if (backtrace(frames, 32) < 4)
        throw std::logic_error("backtrace");
    throw std::runtime_error("expected");
}

int main() {
    if (state != 7)
        return 1;
    try {
        raise_error();
    } catch (const std::runtime_error &) {
        if (state != 12)
            return 2;
        state = 19;
        std::puts("catch-cleanup-unwind-ok");
        return 0;
    }
    return 3;
}
