#include <cstdio>
#include <cstdlib>

int main() {
    char *name = getenv("QUERY_STRING");
    printf("Content-Type: text/plain\r\n\r\n");
    printf("Hello %s", name ? name : "world");
    return 0;
}
