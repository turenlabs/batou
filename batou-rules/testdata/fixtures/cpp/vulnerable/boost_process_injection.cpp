// VULN: Command injection via Boost.Process with tainted input.
// Should trigger detection for cpp.boost.process.child and cpp.boost.process.system sinks.

#include <boost/process.hpp>
#include <string>
#include <cstdlib>
namespace bp = boost::process;

void run_user_tool() {
    char *tool = getenv("TOOL_PATH");

    // Vulnerable: tainted input used as command
    bp::child c(std::string(tool));
    c.wait();
}

void execute_command() {
    char *cmd = getenv("CMD");

    // Vulnerable: tainted input in system call
    bp::system(std::string(cmd));
}
