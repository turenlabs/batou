#include <cstdio>

void make_header(const char *host, const char *path) {
    char header[128];
    sprintf(header, "GET %s HTTP/1.1\r\nHost: %s\r\n", path, host);
}
