#include <unistd.h>
#include <string.h>

void safe_tool(const char *action) {
    const char *allowed[] = {"start", "stop", "restart", NULL};
    for (int i = 0; allowed[i]; i++) {
        if (strcmp(action, allowed[i]) == 0) {
            char *args[] = {"service", (char *)action, NULL};
            execvp("service", args);
            return;
        }
    }
}
