#include <filesystem>
#include <fstream>
#include <string>

void safe_log(const std::string &logname) {
    auto resolved = std::filesystem::canonical("/var/log/app/" + logname);
    if (!resolved.string().starts_with("/var/log/app/")) return;
    std::ofstream file(resolved, std::ios::app);
}
