#include <stdio.h>

void render(const char *text) {
    char buf[1024];
    snprintf(buf, sizeof(buf), "%s", text);
}
