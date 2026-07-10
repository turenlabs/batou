#include <stdio.h>
#include <stdlib.h>

void convert_file(const char *input_file, const char *output_file) {
    char cmd[512];
    sprintf(cmd, "convert %s %s", input_file, output_file);
    system(cmd);
}
