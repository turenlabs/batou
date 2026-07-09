#include <unistd.h>
#include <cstdlib>
#include <cstdio>
#include <sys/wait.h>

void safe_kill(const char *pid_str) {
    int pid_val = atoi(pid_str);
    if (pid_val > 0 && pid_val < 65536) {
        char buf[16];
        snprintf(buf, sizeof(buf), "%d", pid_val);
        char *args[] = {(char *)"kill", (char *)"-TERM", buf, nullptr};
        execvp("kill", args);
    }
}
