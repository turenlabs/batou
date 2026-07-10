#include <cstdio>
#include <cstdlib>

int main() {
    char *data = getenv("QUERY_STRING");
    fprintf(stdout, "Content-Type: text/html\r\n\r\n");
    fprintf(stdout, "<html><body><textarea>%s</textarea></body></html>", data);
    return 0;
}
