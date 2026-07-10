#include <stdio.h>
#include <stdlib.h>

void grep_file(const char *pattern) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "grep '%s' /var/log/syslog", pattern);
    system(cmd);
}
