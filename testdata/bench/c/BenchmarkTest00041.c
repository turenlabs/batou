#include <stdio.h>

void read_file(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (fp) {
        char buf[4096];
        fread(buf, 1, sizeof(buf), fp);
        fclose(fp);
    }
}
