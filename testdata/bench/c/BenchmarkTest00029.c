#include <stdio.h>
#include <stdlib.h>

void check_host(const char *hostname) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "nslookup %s", hostname);
    FILE *fp = popen(cmd, "r");
    if (fp) pclose(fp);
}
