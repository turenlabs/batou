// VULN: Unchecked vector access via operator[] with user-controlled index.
// Should trigger detection for cpp.stl.operator.bracket sink.

#include <iostream>
#include <vector>
#include <string>
#include <cstdlib>

class UserDatabase {
public:
    std::vector<std::string> users;

    UserDatabase() {
        users.push_back("alice");
        users.push_back("bob");
        users.push_back("charlie");
    }

    std::string get_user(int index) {
        // Vulnerable: operator[] does NOT perform bounds checking.
        // If index is out of range, this is undefined behavior.
        return users[index];
    }
};

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <user-index>" << std::endl;
        return 1;
    }

    int index = atoi(argv[1]);
    UserDatabase db;

    // User-controlled index flows into unchecked vector access
    std::string user = db.get_user(index);
    std::cout << "User: " << user << std::endl;

    return 0;
}
