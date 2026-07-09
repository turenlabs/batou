#include <string.h>

void safe_copy(const char *input) {
    char buf[64];
    strlcpy(buf, input, sizeof(buf));
}
