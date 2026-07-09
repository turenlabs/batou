#include <cstdio>

void read_config(const char *config_name) {
    char path[256];
    snprintf(path, sizeof(path), "/etc/app/%s", config_name);
    FILE *fp = fopen(path, "r");
    if (fp) fclose(fp);
}
