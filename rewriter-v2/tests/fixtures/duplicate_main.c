int duplicate_a(void);
int duplicate_b(void);
const void *address_a(void);
const void *address_b(void);

int main(void) {
    return duplicate_a() != 113 || duplicate_b() != 129 || address_a() == address_b();
}
