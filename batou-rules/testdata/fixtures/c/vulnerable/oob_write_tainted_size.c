/* VULN: Out-of-bounds write (CWE-787). The copy length comes from a
 * caller-controlled function parameter and the destination is a fixed-size
 * stack buffer, so a length larger than the buffer overruns it.
 * Should trigger BATOU-CAST-004.
 */
#include <string.h>
#include <stddef.h>

/* len is attacker-controllable (passed by the caller); dst is bounded. */
void copy_into_record(int len, const char *src) {
    char dst[64];
    memcpy(dst, src, len);   /* CWE-787: len may exceed sizeof(dst) */
}

void move_into_buf(size_t n, const char *p) {
    char buf[128];
    memmove(buf, p, n);      /* CWE-787: n is caller-controlled */
}
