#include <spawn.h>
#include <sys/wait.h>

void safe_cat(const char *filename) {
    pid_t pid;
    char *args[] = {(char *)"cat", (char *)filename, nullptr};
    extern char **environ;
    posix_spawn(&pid, "/bin/cat", nullptr, nullptr, args, environ);
    waitpid(pid, nullptr, 0);
}
