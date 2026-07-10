/* SAFE: bounded copies. Length is a literal or sizeof of the destination, and
 * allocation sizes use a constant factor. Should NOT trigger BATOU-CAST-004 or
 * BATOU-CAST-005.
 */
#include <string.h>
#include <stdlib.h>
#include <stddef.h>

void copy_bounded(const char *src) {
    char dst[64];
    memcpy(dst, src, sizeof(dst));   /* bounded by destination size */
}

void *make_array(int n) {
    return malloc(n * sizeof(int));  /* constant factor: not an overflow shape */
}

void *make_n(int n) {
    return malloc(n);                /* single operand: no multiplication */
}
