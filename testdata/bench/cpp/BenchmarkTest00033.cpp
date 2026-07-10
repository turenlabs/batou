#include <string>
#include <vector>

void safe_exec(const std::string &filename) {
    // QProcess equivalent: separate program and args
    std::vector<std::string> args = {"cat", filename};
    // QProcess::execute(args[0], {args[1]});
}
