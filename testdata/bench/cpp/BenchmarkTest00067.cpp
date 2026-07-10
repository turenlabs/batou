#include <cstdio>
#include <cstdarg>

void log_message(const char *fmt, ...) {
    char buf[128];
    va_list args;
    va_start(args, fmt);
    vsprintf(buf, fmt, args);
    va_end(args);
}
