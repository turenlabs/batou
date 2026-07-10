#include <stdio.h>

void get_uptime(void) {
    FILE *fp = popen("uptime", "r");
    char buf[256];
    if (fp) {
        fgets(buf, sizeof(buf), fp);
        pclose(fp);
    }
}
