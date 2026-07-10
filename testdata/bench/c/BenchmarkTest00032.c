#include <unistd.h>

void list_files(void) {
    char *args[] = {"/bin/ls", "-la", "/tmp", NULL};
    execv("/bin/ls", args);
}
