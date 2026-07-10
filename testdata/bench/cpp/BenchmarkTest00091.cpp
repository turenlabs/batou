#include <cstdio>
#include <cstdlib>
#include <cstring>

void html_encode(const char *input, char *output, size_t out_size) {
    size_t j = 0;
    for (size_t i = 0; input[i] && j < out_size - 6; i++) {
        switch (input[i]) {
            case '<': j += snprintf(output + j, out_size - j, "&lt;"); break;
            case '>': j += snprintf(output + j, out_size - j, "&gt;"); break;
            case '&': j += snprintf(output + j, out_size - j, "&amp;"); break;
            case '"': j += snprintf(output + j, out_size - j, "&quot;"); break;
            default: output[j++] = input[i]; break;
        }
    }
    output[j] = '\0';
}

int main() {
    char *name = getenv("QUERY_STRING");
    char safe[4096];
    html_encode(name ? name : "", safe, sizeof(safe));
    printf("Content-Type: text/html\r\n\r\n");
    printf("<html><body><h1>Hello %s</h1></body></html>", safe);
    return 0;
}
