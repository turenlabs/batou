// VULN: Command injection via system() with user input.
// Should trigger detection for cpp.system sink with tainted input.

#include <cstdlib>
#include <iostream>
#include <string>

void check_host(const std::string &hostname) {
    // Vulnerable: user input concatenated into shell command
    std::string command = "nslookup " + hostname;

    // system() passes the command to /bin/sh -c, allowing injection
    int result = system(command.c_str());
    if (result != 0) {
        std::cerr << "Command failed with code: " << result << std::endl;
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <hostname>" << std::endl;
        return 1;
    }

    // Attacker input: "example.com; cat /etc/passwd"
    check_host(argv[1]);
    return 0;
}
