#include <fcntl.h>
#include <unistd.h>

void read_config(const char *config_name) {
    char path[256];
    snprintf(path, sizeof(path), "/etc/app/%s", config_name);
    int fd = open(path, O_RDONLY);
    if (fd >= 0) close(fd);
}
