#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/wait.h>

void safe_kill(const char *pid_str) {
    int pid = atoi(pid_str);
    if (pid > 0 && pid < 65536) {
        char buf[16];
        snprintf(buf, sizeof(buf), "%d", pid);
        char *args[] = {"kill", "-TERM", buf, NULL};
        execvp("kill", args);
    }
}
