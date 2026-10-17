#include <stdio.h>

static volatile int state;

__attribute__((noinline)) static int choose(int value) {
    switch (value) {
    case 0: state += 2; break;
    case 1: state -= 3; break;
    case 2: state ^= 0x71; break;
    case 3: state *= 5; break;
    case 4: state += 17; break;
    case 5: state ^= 0x33; break;
    case 6: state -= 11; break;
    case 7: state *= 2; break;
    default: state = -1; break;
    }
    return state;
}

int main(void) {
    int sum = 0;
    for (int i = 0; i != 9; ++i)
        sum += choose(i);
    printf("switch=%d\n", sum);
    return 0;
}
