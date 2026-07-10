#include <string.h>
#include <stdlib.h>

void store(const char *data) {
    char *buf = (char *)malloc(32);
    strcpy(buf, data);
    free(buf);
}
