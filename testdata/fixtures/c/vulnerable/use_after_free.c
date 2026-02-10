/* VULN: Use-after-free - accessing a struct member after free().
 * Should trigger GTSS-MEM-004 (Memory Management Issue: use-after-free).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct User {
    int id;
    char name[64];
    int is_admin;
};

void process_user(struct User *user) {
    printf("Processing user: %s (id=%d)\n", user->name, user->id);

    /* Free the user struct */
    free(user);

    /* Vulnerable: accessing user->name after free.
     * The memory may have been reallocated and overwritten.
     */
    printf("Done processing: %s\n", user->name);

    if (user->is_admin) {
        printf("Admin access granted\n");
    }
}

int main(void) {
    struct User *user = malloc(sizeof(struct User));
    if (user == NULL) {
        return 1;
    }

    user->id = 42;
    strncpy(user->name, "alice", sizeof(user->name) - 1);
    user->is_admin = 0;

    process_user(user);
    return 0;
}
