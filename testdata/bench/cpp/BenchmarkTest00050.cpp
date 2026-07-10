#include <cstdio>

void redirect_output(const char *logfile) {
    freopen(logfile, "a", stdout);
}
