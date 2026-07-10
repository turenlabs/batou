#include <string>
#include <iostream>
#include <cstdlib>

int main() {
    char *input = getenv("QUERY_STRING");
    std::string html = "<html><body><p>" + std::string(input ? input : "") + "</p></body></html>";
    std::cout << "Content-Type: text/html\r\n\r\n" << html;
    return 0;
}
