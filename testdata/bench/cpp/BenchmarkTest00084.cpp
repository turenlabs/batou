#include <cstdio>
#include <cstdlib>

int main() {
    char *name = getenv("QUERY_STRING");
    printf("Content-Type: text/html\r\n\r\n");
    fputs("<html><body><input value='", stdout);
    fputs(name, stdout);
    fputs("'></body></html>", stdout);
    return 0;
}
