#include <unistd.h>
#include <string.h>

void run_safe(const char *input) {
    if (strcmp(input, "status") == 0 || strcmp(input, "version") == 0) {
        char *args[] = {"mytool", (char *)input, NULL};
        execvp("mytool", args);
    }
}
