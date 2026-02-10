// SAFE: std::string instead of char arrays - no manual buffer management.
// Should NOT trigger GTSS-MEM-001 or buffer overflow rules.

#include <iostream>
#include <string>
#include <algorithm>

class Logger {
public:
    void log(const std::string &message) {
        // Safe: std::string manages its own memory, no overflow possible
        std::string formatted = "[LOG] " + message;
        std::cout << formatted << std::endl;
        logs_.push_back(formatted);
    }

    void log_sanitized(const std::string &user_input) {
        // Safe: sanitize by removing control characters
        std::string sanitized = user_input;
        sanitized.erase(
            std::remove_if(sanitized.begin(), sanitized.end(),
                           [](char c) { return c < 32 && c != '\t'; }),
            sanitized.end());

        // Safe: using string formatting, not printf with user data
        std::cout << "Input: " << sanitized << std::endl;
        logs_.push_back("User: " + sanitized);
    }

    size_t log_count() const { return logs_.size(); }

private:
    std::vector<std::string> logs_;
};

int main(int argc, char *argv[]) {
    Logger logger;

    if (argc >= 2) {
        // Safe: std::string handles arbitrary-length input
        std::string input(argv[1]);
        logger.log(input);
        logger.log_sanitized(input);
    }

    logger.log("Application started");
    std::cout << "Total logs: " << logger.log_count() << std::endl;
    return 0;
}
