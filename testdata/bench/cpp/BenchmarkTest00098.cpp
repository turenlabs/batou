#include <cstdio>
#include <cstdlib>

int main() {
    printf("Content-Type: text/html\r\n");
    printf("Content-Security-Policy: default-src 'self'\r\n\r\n");
    printf("<html><body><p>Protected page</p></body></html>");
    return 0;
}
