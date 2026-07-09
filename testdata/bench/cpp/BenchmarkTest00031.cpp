#include <unistd.h>

void run_command(const char *filename) {
    char *args[] = {(char *)"ls", (char *)"-l", (char *)filename, nullptr};
    execvp("ls", args);
}
