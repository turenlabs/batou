#include <stdio.h>

void write_data(const char *filename, const char *data) {
    FILE *fp = fopen(filename, "w");
    if (fp) {
        fputs(data, fp);
        fclose(fp);
    }
}
