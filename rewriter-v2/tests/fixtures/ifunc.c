static volatile int selection = 1;
static volatile int addition = 29;

static int implementation(int value) {
    return value + addition;
}

static int alternative(int value) {
    return value - addition;
}

__attribute__((noinline)) static int (*resolve(void))(int) {
    return selection ? implementation : alternative;
}

int exported_ifunc(int) __attribute__((ifunc("resolve")));
static int local_ifunc(int) __attribute__((ifunc("resolve")));

int call_ifunc(int value) {
    return local_ifunc(value) + exported_ifunc(value);
}

int (*ifunc_pointer)(int) = local_ifunc;

int exercise_resolver(int value) {
    return resolve()(value);
}
