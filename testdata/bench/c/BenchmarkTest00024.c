#include <string.h>
#include <stdlib.h>

void compile_file(const char *filename) {
    char cmd[512];
    strcpy(cmd, "gcc -o output ");
    strcat(cmd, filename);
    system(cmd);
}
