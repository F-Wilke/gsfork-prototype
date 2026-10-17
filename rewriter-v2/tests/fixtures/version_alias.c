__attribute__((noinline)) int old_api(void) { return 13; }
__attribute__((noinline)) int new_api(void) { return 29; }

__asm__(".symver old_api,version_api@VERS_1");
__asm__(".symver new_api,version_api@@VERS_2");

static int (*volatile functions[])(void) = {old_api, new_api};

int call_versions(void) {
    return functions[0]() * 100 + functions[1]();
}
