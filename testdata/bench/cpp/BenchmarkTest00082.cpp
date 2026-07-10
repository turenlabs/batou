#include <iostream>
#include <cstdlib>

int main() {
    std::cout << "Content-Type: text/html\r\n\r\n";
    char *query = getenv("QUERY_STRING");
    std::cout << "<html><body><p>" << query << "</p></body></html>";
    return 0;
}
