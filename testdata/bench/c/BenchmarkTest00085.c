#include <syslog.h>

void log_event(const char *user_msg) {
    syslog(LOG_INFO, user_msg);
}
