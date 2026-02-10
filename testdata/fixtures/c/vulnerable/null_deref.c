/* VULN: Null pointer dereference - malloc return not checked for NULL.
 * Should trigger GTSS-MEM-006 (Null Pointer Dereference).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct Config {
    char hostname[256];
    int port;
    int max_connections;
};

struct Config *create_config(const char *hostname, int port) {
    /* Vulnerable: malloc return value not checked for NULL.
     * If allocation fails (OOM), the subsequent writes dereference NULL.
     */
    struct Config *config = malloc(sizeof(struct Config));

    strncpy(config->hostname, hostname, sizeof(config->hostname) - 1);
    config->hostname[sizeof(config->hostname) - 1] = '\0';
    config->port = port;
    config->max_connections = 100;

    return config;
}

int main(void) {
    struct Config *cfg = create_config("db.example.com", 5432);
    printf("Config: %s:%d (max=%d)\n", cfg->hostname, cfg->port, cfg->max_connections);
    free(cfg);
    return 0;
}
