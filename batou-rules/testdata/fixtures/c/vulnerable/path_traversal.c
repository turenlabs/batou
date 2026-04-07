/* VULN: Path traversal via fopen with unsanitized user-provided path.
 * Should trigger detection for c.file.fopen sink with tainted input.
 */

#include <stdio.h>
#include <stdlib.h>

void read_config(const char *filename) {
    char buf[4096];

    /* Vulnerable: user controls the filename, can use "../../../etc/passwd" */
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        perror("fopen");
        return;
    }

    while (fgets(buf, sizeof(buf), fp) != NULL) {
        printf("%s", buf);
    }

    fclose(fp);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <config-file>\n", argv[0]);
        return 1;
    }

    read_config(argv[1]);
    return 0;
}
