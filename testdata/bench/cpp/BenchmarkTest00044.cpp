#include <fstream>
#include <string>

void load_template(const std::string &template_name) {
    std::string path = "/var/templates/" + template_name;
    std::ifstream file(path);
    std::string content;
    std::getline(file, content);
}
