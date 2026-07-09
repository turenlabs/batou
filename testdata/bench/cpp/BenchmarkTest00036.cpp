#include <cstdio>

void get_uptime() {
    FILE *fp = popen("uptime", "r");
    char buf[256];
    if (fp) {
        fgets(buf, sizeof(buf), fp);
        pclose(fp);
    }
}
