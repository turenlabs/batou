/* VULN: Integer overflow in allocation size (CWE-190). The size multiplies two
 * unchecked values which can wrap size_t, under-allocating the buffer.
 * Should trigger BATOU-CAST-005.
 */
#include <stdlib.h>

void *make_grid(int width, int height) {
    /* width * height can overflow; no overflow guard before malloc. */
    return malloc(width * height);   /* CWE-190 */
}

char *make_table(unsigned rows, unsigned cols) {
    return calloc(rows, cols * cols);  /* per-element size cols*cols can wrap */
}
