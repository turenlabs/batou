/* VULN: Double free - calling free() twice on the same pointer.
 * Should trigger GTSS-MEM-004 (Memory Management Issue: double-free).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct Connection {
    int socket_fd;
    char *buffer;
    size_t buffer_size;
};

void close_connection(struct Connection *conn) {
    if (conn->buffer != NULL) {
        free(conn->buffer);
    }
    printf("Connection on fd %d closed\n", conn->socket_fd);
}

void cleanup(struct Connection *conn) {
    close_connection(conn);

    /* Vulnerable: conn->buffer was already freed in close_connection.
     * This second free corrupts the heap allocator.
     */
    free(conn->buffer);
    free(conn);
}

int main(void) {
    struct Connection *conn = malloc(sizeof(struct Connection));
    if (conn == NULL) {
        return 1;
    }

    conn->socket_fd = 42;
    conn->buffer_size = 1024;
    conn->buffer = malloc(conn->buffer_size);
    if (conn->buffer == NULL) {
        free(conn);
        return 1;
    }

    memset(conn->buffer, 0, conn->buffer_size);
    cleanup(conn);
    return 0;
}
