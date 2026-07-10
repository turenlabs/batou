#include <sstream>
#include <iostream>
#include <cstdlib>

int main() {
    char *val = getenv("QUERY_STRING");
    std::ostringstream oss;
    oss << "<html><body><div class='msg'>" << (val ? val : "") << "</div></body></html>";
    std::cout << "Content-Type: text/html\r\n\r\n" << oss.str();
    return 0;
}
