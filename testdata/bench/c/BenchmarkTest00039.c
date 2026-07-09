#include <unistd.h>

void cleanup(void) {
    char *args[] = {"/bin/rm", "-rf", "/tmp/cache", NULL};
    execv("/bin/rm", args);
}
