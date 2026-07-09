#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

void safe_write(const char *name, const char *data, int len) {
    char input_path[512];
    char resolved[PATH_MAX];
    snprintf(input_path, sizeof(input_path), "/tmp/uploads/%s", name);
    if (realpath(input_path, resolved) == NULL) return;
    if (strncmp(resolved, "/tmp/uploads/", 13) != 0) return;
    int fd = open(resolved, O_WRONLY | O_CREAT, 0644);
    if (fd >= 0) {
        write(fd, data, len);
        close(fd);
    }
}
