#include <cstdio>
#include <cstdlib>

int main() {
    char *id = getenv("QUERY_STRING");
    int user_id = id ? atoi(id) : 0;
    printf("Content-Type: text/html\r\n\r\n");
    printf("<html><body><p>User ID: %d</p></body></html>", user_id);
    return 0;
}
