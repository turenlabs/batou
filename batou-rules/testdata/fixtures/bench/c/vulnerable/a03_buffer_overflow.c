// Source: CWE-120/CWE-787 - Classic buffer overflow patterns
// Expected: BATOU-MEM-001 (Banned Function - gets/strcpy/sprintf), BATOU-MEM-003 (Buffer Overflow)
// OWASP: A03:2021 - Injection (Buffer Overflow leading to code execution)

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

struct user_session {
    char username[32];
    char role[16];
    int is_admin;
};

void authenticate(const char *input_user, const char *input_pass) {
    char username[64];
    char password[64];
    strcpy(username, input_user);
    strcpy(password, input_pass);

    char query[256];
    sprintf(query, "SELECT * FROM users WHERE user='%s' AND pass='%s'", username, password);
    printf("Query: %s\n", query);
}

void read_user_input(void) {
    char buffer[128];
    printf("Enter command: ");
    gets(buffer);
    printf("You entered: %s\n", buffer);
}

void process_request(const char *data, size_t len) {
    char local_buf[256];
    memcpy(local_buf, data, len);
    local_buf[len] = '\0';
    printf("Processing: %s\n", local_buf);
}
