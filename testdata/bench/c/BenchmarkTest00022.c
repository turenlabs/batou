#include <stdio.h>
#include <stdlib.h>

void ping_host(const char *host) {
    char cmd[256];
    sprintf(cmd, "ping -c 1 %s", host);
    system(cmd);
}
