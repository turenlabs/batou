#include <cstdio>
#include <cstdlib>

int main() {
    char *user = getenv("QUERY_STRING");
    char buf[2048];
    snprintf(buf, sizeof(buf), "<html><body><span>%s</span></body></html>", user);
    printf("Content-Type: text/html\r\n\r\n%s", buf);
    return 0;
}
