// VULN: Buffer overflow via strcpy into fixed-size char array.
// Should trigger GTSS-MEM-001 (Banned Functions: strcpy) for C++.

#include <cstdio>
#include <cstring>
#include <iostream>

class Logger {
public:
    void log(const char *message) {
        char buffer[128];
        // Vulnerable: strcpy has no bounds checking
        strcpy(buffer, message);
        std::cout << "[LOG] " << buffer << std::endl;
    }
};

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <message>" << std::endl;
        return 1;
    }

    Logger logger;
    // User input from argv flows into strcpy
    logger.log(argv[1]);
    return 0;
}
