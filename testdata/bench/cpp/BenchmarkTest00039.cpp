#include <unistd.h>

void cleanup() {
    char *args[] = {(char *)"/bin/rm", (char *)"-rf", (char *)"/tmp/cache", nullptr};
    execv("/bin/rm", args);
}
