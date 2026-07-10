#include <iostream>
#include <cstdlib>
#include <string>

int main() {
    char *comment = getenv("QUERY_STRING");
    std::string html = "<html><body><div>" + std::string(comment ? comment : "") + "</div></body></html>";
    std::cout << "Content-Type: text/html\r\n\r\n";
    std::cout << html;
    return 0;
}
