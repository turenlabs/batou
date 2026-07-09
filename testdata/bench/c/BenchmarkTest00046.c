#include <stdio.h>

void move_file(const char *src, const char *dst) {
    rename(src, dst);
}
