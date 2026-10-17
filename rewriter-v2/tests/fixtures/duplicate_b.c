static volatile int repeated = 29;

int duplicate_b(void) {
    return repeated + __PRETTY_FUNCTION__[0];
}

const void *address_b(void) {
    return (const void *)&repeated;
}
