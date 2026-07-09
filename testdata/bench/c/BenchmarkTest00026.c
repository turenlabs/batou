#include <stdio.h>
#include <stdlib.h>

void list_dir(const char *path) {
    char cmd[256];
    sprintf(cmd, "ls -la %s", path);
    FILE *fp = popen(cmd, "r");
    char buf[1024];
    while (fgets(buf, sizeof(buf), fp)) {
        printf("%s", buf);
    }
    pclose(fp);
}
