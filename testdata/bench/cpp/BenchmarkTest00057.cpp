#include <cstdio>
#include <cstdlib>

void read_by_id(const char *id_str) {
    int id = atoi(id_str);
    char path[256];
    snprintf(path, sizeof(path), "/data/files/%d.dat", id);
    FILE *fp = fopen(path, "r");
    if (fp) fclose(fp);
}
