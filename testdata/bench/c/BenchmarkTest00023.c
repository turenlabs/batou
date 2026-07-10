#include <stdio.h>
#include <stdlib.h>

void read_output(const char *user_cmd) {
    char cmd[256];
    sprintf(cmd, "ls %s", user_cmd);
    FILE *fp = popen(cmd, "r");
    if (fp) pclose(fp);
}
