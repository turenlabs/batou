#include <cstdio>
#include <cstdlib>

void compile_file(const char *filename) {
    char cmd[512];
    sprintf(cmd, "gcc -o output %s", filename);
    system(cmd);
}
