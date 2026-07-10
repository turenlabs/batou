#include <cstdio>

void format_msg(const char *user, const char *msg) {
    char buf[128];
    snprintf(buf, sizeof(buf), "User %s says: %s", user, msg);
}
