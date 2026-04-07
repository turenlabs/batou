/* SAFE: malloc with NULL check and size validation before use.
 * Should NOT trigger GTSS-MEM-006 or GTSS-MEM-005.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_RECORDS 1000000

struct Record {
    int id;
    char name[64];
    double value;
};

struct Record *allocate_records(size_t count) {
    /* Safe: validate count to prevent integer overflow */
    if (count == 0 || count > MAX_RECORDS) {
        return NULL;
    }

    /* Safe: check for multiplication overflow before malloc */
    if (count > SIZE_MAX / sizeof(struct Record)) {
        return NULL;
    }

    struct Record *records = calloc(count, sizeof(struct Record));
    /* Safe: NULL check after allocation */
    if (records == NULL) {
        fprintf(stderr, "allocation failed for %zu records\n", count);
        return NULL;
    }

    return records;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <count>\n", argv[0]);
        return 1;
    }

    long val = strtol(argv[1], NULL, 10);
    if (val <= 0) {
        fprintf(stderr, "count must be positive\n");
        return 1;
    }

    size_t count = (size_t)val;
    struct Record *records = allocate_records(count);
    if (records == NULL) {
        return 1;
    }

    records[0].id = 1;
    printf("Allocated %zu records\n", count);
    free(records);
    return 0;
}
