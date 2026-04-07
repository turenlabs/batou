// Source: CWE-78 - OS Command Injection via argv in C++
// Expected: BATOU-INJ, TAINT
// OWASP: A03:2021 - Injection (Command Injection)

#include <cstdlib>
#include <iostream>
#include <string>

void runUserCommand(int argc, char* argv[]) {
    if (argc < 2) return;
    std::string cmd = "ls -la ";
    cmd += argv[1];
    system(cmd.c_str());
}

int main(int argc, char* argv[]) {
    runUserCommand(argc, argv);
    return 0;
}
