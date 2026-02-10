/* VULN: Integer overflow in malloc size calculation.
 * Should trigger GTSS-MEM-005 (Integer Overflow in Allocation).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct Record {
    int id;
    char name[64];
    double value;
};

struct Record *allocate_records(size_t count) {
    /* Vulnerable: count * sizeof(struct Record) can overflow to a small value,
     * resulting in an undersized buffer. Subsequent writes overflow the heap.
     */
    struct Record *records = malloc(count * sizeof(struct Record));
    if (records == NULL) {
        return NULL;
    }
    memset(records, 0, count * sizeof(struct Record));
    return records;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <count>\n", argv[0]);
        return 1;
    }

    size_t count = (size_t)atol(argv[1]);
    struct Record *records = allocate_records(count);
    if (records == NULL) {
        fprintf(stderr, "allocation failed\n");
        return 1;
    }

    records[0].id = 1;
    printf("Allocated %zu records\n", count);
    free(records);
    return 0;
}
