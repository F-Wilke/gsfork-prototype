static volatile int repeated = 13;

int duplicate_a(void) {
    return repeated + __PRETTY_FUNCTION__[0];
}

const void *address_a(void) {
    return (const void *)&repeated;
}
