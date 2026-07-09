#include <cstdio>
#include <cstdlib>

int main() {
    printf("Content-Type: text/html\r\n\r\n");
    char *name = getenv("QUERY_STRING");
    printf("<html><body><h1>Hello %s</h1></body></html>", name);
    return 0;
}
