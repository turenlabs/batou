#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void run_tool(const char *arg) {
    char buf[128];
    char cmd[256];
    strcpy(buf, arg);
    sprintf(cmd, "tool --input %s", buf);
    system(cmd);
}
