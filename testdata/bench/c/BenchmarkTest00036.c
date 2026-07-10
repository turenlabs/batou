#include <spawn.h>
#include <sys/wait.h>

void safe_exec(const char *filename) {
    pid_t pid;
    char *args[] = {"cat", (char *)filename, NULL};
    extern char **environ;
    posix_spawn(&pid, "/bin/cat", NULL, NULL, args, environ);
    waitpid(pid, NULL, 0);
}
