#include <stdio.h>
#include <string.h>

void read_allowed(const char *name) {
    const char *allowed[] = {"readme.txt", "help.txt", "license.txt", NULL};
    int found = 0;
    for (int i = 0; allowed[i]; i++) {
        if (strcmp(name, allowed[i]) == 0) { found = 1; break; }
    }
    if (!found) return;
    char path[256];
    snprintf(path, sizeof(path), "/docs/%s", name);
    FILE *fp = fopen(path, "r");
    if (fp) fclose(fp);
}
