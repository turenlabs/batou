#include <string>
#include <cstdlib>

void run_command(const std::string &user_input) {
    system(user_input.c_str());
}
