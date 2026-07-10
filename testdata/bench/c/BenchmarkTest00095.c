#include <syslog.h>

void log_event(const char *user_msg) {
    syslog(LOG_INFO, "Event: %s", user_msg);
}
