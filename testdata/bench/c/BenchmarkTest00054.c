#include <stdio.h>

void read_config(void) {
    FILE *fp = fopen("/etc/app/config.ini", "r");
    if (fp) {
        char buf[4096];
        fread(buf, 1, sizeof(buf), fp);
        fclose(fp);
    }
}
