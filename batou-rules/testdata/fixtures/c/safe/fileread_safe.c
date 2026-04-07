/* SAFE: File-read operations with hardcoded paths — no path traversal risk. */

#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <glob.h>

void list_config_dir(void) {
    DIR *d = opendir("/etc/myapp/conf.d");
    if (d) {
        struct dirent *entry;
        while ((entry = readdir(d)) != NULL) {
            printf("%s\n", entry->d_name);
        }
        closedir(d);
    }
}

void check_config_exists(void) {
    struct stat st;
    if (lstat("/etc/myapp/config.ini", &st) == 0) {
        printf("config size: %ld\n", (long)st.st_size);
    }
}

void resolve_config_link(void) {
    char buf[4096];
    ssize_t len = readlink("/etc/myapp/current", buf, sizeof(buf) - 1);
    if (len != -1) {
        buf[len] = '\0';
        printf("current -> %s\n", buf);
    }
}

void canonical_config(void) {
    char *resolved = realpath("/etc/myapp/config.ini", NULL);
    if (resolved) {
        printf("real: %s\n", resolved);
        free(resolved);
    }
}

int main(void) {
    list_config_dir();
    check_config_exists();
    resolve_config_link();
    canonical_config();
    return 0;
}
