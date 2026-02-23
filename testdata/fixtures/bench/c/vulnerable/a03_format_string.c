// Source: CWE-134 - Format string vulnerability
// Expected: BATOU-MEM-002 (Format String Vulnerability), BATOU-MEM-001 (Banned Function - sprintf)
// OWASP: A03:2021 - Injection (Format String)

#include <stdio.h>
#include <string.h>
#include <syslog.h>

void log_user_action(const char *username, const char *action) {
    char message[512];
    snprintf(message, sizeof(message), "User %s performed: ", username);
    strncat(message, action, sizeof(message) - strlen(message) - 1);
    printf(message);
    syslog(LOG_INFO, message);
}

void display_error(const char *user_input) {
    char error_msg[256];
    snprintf(error_msg, sizeof(error_msg), "Error processing: %s", user_input);
    fprintf(stderr, error_msg);
}

void log_request(const char *method, const char *path) {
    char log_entry[1024];
    sprintf(log_entry, "[%s] %s", method, path);
    printf(log_entry);
}
