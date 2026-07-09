#include <unistd.h>

void run_command(const char *filename) {
    char *args[] = {"ls", "-l", (char *)filename, NULL};
    execvp("ls", args);
}
