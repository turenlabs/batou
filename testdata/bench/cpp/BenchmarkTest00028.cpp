#include <cstdio>
#include <cstdlib>

void run_tool(const char *arg) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "tool --input %s", arg);
    system(cmd);
}
