// Source: CWE-78 - OS Command Injection in C
// Expected: BATOU-MEM-001 (Banned Function - sprintf), BATOU-MEM-011 (system with variable), BATOU-MEM-010 (popen with variable)
// OWASP: A03:2021 - Injection (OS Command Injection)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void ping_host(const char *hostname) {
    char command[256];
    sprintf(command, "ping -c 4 %s", hostname);
    system(command);
}

void convert_file(const char *input_path, const char *format) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "ffmpeg -i %s output.%s", input_path, format);
    system(cmd);
}

int check_dns(const char *domain) {
    char buf[256];
    sprintf(buf, "nslookup %s", domain);
    FILE *fp = popen(buf, "r");
    if (!fp) return -1;
    char result[1024];
    while (fgets(result, sizeof(result), fp)) {
        printf("%s", result);
    }
    return pclose(fp);
}
