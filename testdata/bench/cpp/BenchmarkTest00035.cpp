#include <unistd.h>
#include <cstring>

void run_safe(const char *input) {
    if (strcmp(input, "status") == 0 || strcmp(input, "version") == 0) {
        char *args[] = {(char *)"mytool", (char *)input, nullptr};
        execvp("mytool", args);
    }
}
