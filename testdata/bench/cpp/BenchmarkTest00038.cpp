#include <unistd.h>
#include <cstring>
#include <string>

void safe_tool(const std::string &action) {
    const char *allowed[] = {"start", "stop", "restart", nullptr};
    bool ok = false;
    for (int i = 0; allowed[i]; i++) {
        if (action == allowed[i]) { ok = true; break; }
    }
    if (!ok) return;
    char *args[] = {(char *)"service", (char *)action.c_str(), nullptr};
    execvp("service", args);
}
