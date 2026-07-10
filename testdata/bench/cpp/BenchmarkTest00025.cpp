#include <sstream>
#include <cstdlib>

void grep_file(const std::string &pattern) {
    std::ostringstream oss;
    oss << "grep '" << pattern << "' /var/log/syslog";
    system(oss.str().c_str());
}
