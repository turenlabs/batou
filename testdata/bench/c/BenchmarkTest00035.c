#include <unistd.h>
#include <sys/wait.h>

void safe_ping(const char *host) {
    pid_t pid = fork();
    if (pid == 0) {
        char *args[] = {"ping", "-c", "1", (char *)host, NULL};
        execvp("ping", args);
    }
    wait(NULL);
}
