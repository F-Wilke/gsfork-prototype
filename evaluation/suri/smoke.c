#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    for (int i=1; i+1<argc; i++) {
        if (strcmp(argv[i], "-o") != 0) continue;
        FILE *out = fopen(argv[i+1], "w");
        if (!out) return 2;
        fputs(".text\n", out);
        return fclose(out) != 0;
    }
    return 1;
}
