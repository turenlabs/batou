/* SAFE: Command execution using execve with argument array instead of system().
 * Should NOT trigger command injection detection.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>
#include <ctype.h>

int is_valid_hostname(const char *hostname) {
    size_t len = strlen(hostname);
    if (len == 0 || len > 253) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        if (!isalnum((unsigned char)hostname[i]) &&
            hostname[i] != '.' && hostname[i] != '-') {
            return 0;
        }
    }
    return 1;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <hostname>\n", argv[0]);
        return 1;
    }

    if (!is_valid_hostname(argv[1])) {
        fprintf(stderr, "Invalid hostname\n");
        return 1;
    }

    /* Safe: execve with separate arguments, no shell interpretation */
    char *args[] = {"/usr/bin/ping", "-c", "3", argv[1], NULL};
    char *envp[] = {NULL};

    pid_t pid = fork();
    if (pid == 0) {
        execve("/usr/bin/ping", args, envp);
        perror("execve");
        _exit(1);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
    }

    return 0;
}
