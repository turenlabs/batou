#include <stdio.h>

void read_input(void) {
    char buf[128];
    fgets(buf, sizeof(buf), stdin);
}
