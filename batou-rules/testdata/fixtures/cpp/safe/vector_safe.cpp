// SAFE: Bounds-checked vector access using .at() instead of operator[].
// Should NOT trigger unchecked access detection.

#include <iostream>
#include <vector>
#include <string>
#include <stdexcept>
#include <cstdlib>

class UserDatabase {
public:
    std::vector<std::string> users;

    UserDatabase() {
        users.push_back("alice");
        users.push_back("bob");
        users.push_back("charlie");
    }

    std::string get_user(size_t index) {
        // Safe: .at() performs bounds checking and throws std::out_of_range
        return users.at(index);
    }
};

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <user-index>" << std::endl;
        return 1;
    }

    long index = strtol(argv[1], nullptr, 10);
    if (index < 0) {
        std::cerr << "Index must be non-negative" << std::endl;
        return 1;
    }

    UserDatabase db;

    try {
        // Safe: .at() throws on out-of-range access
        std::string user = db.get_user(static_cast<size_t>(index));
        std::cout << "User: " << user << std::endl;
    } catch (const std::out_of_range &e) {
        std::cerr << "Error: index out of range (" << e.what() << ")" << std::endl;
        return 1;
    }

    return 0;
}
