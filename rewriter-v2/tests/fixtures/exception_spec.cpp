#include <cstdio>
#include <stdexcept>

__attribute__((noinline)) static void allowed(int n) throw(std::runtime_error) {
    if (n)
        throw std::runtime_error("allowed");
}

__attribute__((noinline)) static int nothrow(int n) throw() {
    return n + 1;
}

int main(int argc, char **) {
    try {
        allowed(nothrow(argc));
    } catch (const std::runtime_error &) {
        std::puts("exception-spec-ok");
        return 0;
    }
    return 1;
}
