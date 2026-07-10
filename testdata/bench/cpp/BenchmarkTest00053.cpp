#include <filesystem>
#include <fstream>
#include <string>

void safe_read(const std::string &input) {
    std::filesystem::path base("/var/www/data");
    auto resolved = std::filesystem::canonical(base / input);
    if (!resolved.string().starts_with(base.string())) return;
    std::ifstream file(resolved);
}
