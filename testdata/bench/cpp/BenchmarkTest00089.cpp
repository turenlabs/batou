#include <cstdio>
#include <cstdlib>

int main() {
    char *url = getenv("QUERY_STRING");
    printf("Content-Type: text/html\r\n\r\n");
    printf("<html><body><a href='%s'>Click</a></body></html>", url);
    return 0;
}
