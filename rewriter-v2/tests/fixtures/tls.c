__thread int exported_tls = 13;
static __thread int private_tls = 29;
static __thread int zero_tls;

int tls_value(void) {
    return exported_tls + private_tls + zero_tls;
}

void tls_change(void) {
    ++exported_tls;
    ++private_tls;
    ++zero_tls;
}
