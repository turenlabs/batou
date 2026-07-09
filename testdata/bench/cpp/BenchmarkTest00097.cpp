#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>

void url_encode(const char *input, char *output, size_t out_size) {
    size_t j = 0;
    for (size_t i = 0; input[i] && j < out_size - 4; i++) {
        if (isalnum(input[i]) || input[i] == '-' || input[i] == '_' || input[i] == '.') {
            output[j++] = input[i];
        } else {
            j += snprintf(output + j, out_size - j, "%%%02X", (unsigned char)input[i]);
        }
    }
    output[j] = '\0';
}

int main() {
    char *q = getenv("QUERY_STRING");
    char safe[4096];
    url_encode(q ? q : "", safe, sizeof(safe));
    printf("Content-Type: text/html\r\n\r\n");
    printf("<html><body><a href='/search?q=%s'>Search</a></body></html>", safe);
    return 0;
}
