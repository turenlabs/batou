#include <string>
#include <iostream>
#include <cstdlib>

std::string escape_html(const std::string &s) {
    std::string result;
    for (char c : s) {
        switch (c) {
            case '<': result += "&lt;"; break;
            case '>': result += "&gt;"; break;
            case '&': result += "&amp;"; break;
            case '"': result += "&quot;"; break;
            default: result += c; break;
        }
    }
    return result;
}

int main() {
    char *input = getenv("QUERY_STRING");
    std::string safe = escape_html(input ? input : "");
    std::cout << "Content-Type: text/html\r\n\r\n";
    std::cout << "<html><body><p>" << safe << "</p></body></html>";
    return 0;
}
