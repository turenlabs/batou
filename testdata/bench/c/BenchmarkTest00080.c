#include <string.h>
#include <stdio.h>

void make_header(const char *host, const char *path) {
    char header[512];
    snprintf(header, sizeof(header), "GET %s HTTP/1.1\r\nHost: %s\r\n", path, host);
}
