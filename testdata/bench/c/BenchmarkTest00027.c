#include <stdio.h>
#include <stdlib.h>

void fetch_url(const char *url) {
    char cmd[512];
    sprintf(cmd, "curl -s %s", url);
    system(cmd);
}
