#include <cstdio>
#include <cstdlib>

int main() {
    char *name = getenv("QUERY_STRING");
    printf("Content-Type: application/json\r\n\r\n");
    printf("{"name": "%s"}", name ? name : "");
    return 0;
}
