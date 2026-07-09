#include <stdio.h>
#include <string.h>

void load_template(const char *template_name) {
    char path[512];
    strcpy(path, "/var/templates/");
    strcat(path, template_name);
    FILE *fp = fopen(path, "r");
    if (fp) fclose(fp);
}
