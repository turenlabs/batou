#include <string>
#include <cstdlib>

void convert(const std::string &input, const std::string &output) {
    std::string cmd = "convert " + input + " " + output;
    system(cmd.c_str());
}
