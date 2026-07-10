#include <stdio.h>

void format_msg(const char *user, const char *msg) {
    char buf[128];
    sprintf(buf, "User %s says: %s", user, msg);
}
