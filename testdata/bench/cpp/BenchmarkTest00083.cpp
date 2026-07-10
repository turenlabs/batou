#include <cstdio>
#include <cstdlib>

int main() {
    char *input = getenv("QUERY_STRING");
    char response[4096];
    sprintf(response, "<html><body><div>%s</div></body></html>", input);
    printf("Content-Type: text/html\r\n\r\n%s", response);
    return 0;
}
