#include <stdio.h>
#include <string.h>

void process_file(const char *user_path) {
    char resolved[512];
    strcpy(resolved, user_path);
    FILE *fp = fopen(resolved, "r");
    if (fp) fclose(fp);
}
