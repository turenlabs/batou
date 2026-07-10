#include <stdio.h>
#include <string.h>

void display(const char *input) {
    char buf[256];
    strcpy(buf, input);
    printf(buf);
}
