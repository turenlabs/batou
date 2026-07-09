#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

void write_upload(const char *name, const char *data, int len) {
    char path[256];
    snprintf(path, sizeof(path), "/tmp/uploads/%s", name);
    int fd = open(path, O_WRONLY | O_CREAT, 0644);
    if (fd >= 0) {
        write(fd, data, len);
        close(fd);
    }
}
