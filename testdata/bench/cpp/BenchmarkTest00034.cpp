#include <unistd.h>
#include <sys/wait.h>

void safe_ping(const char *host) {
    pid_t pid = fork();
    if (pid == 0) {
        char *args[] = {(char *)"ping", (char *)"-c", (char *)"1", (char *)host, nullptr};
        execvp("ping", args);
    }
    wait(nullptr);
}
