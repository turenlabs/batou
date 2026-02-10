// SAFE: Command execution using execve with separate argument array.
// Should NOT trigger command injection detection.

#include <iostream>
#include <string>
#include <algorithm>
#include <cctype>
#include <unistd.h>
#include <sys/wait.h>

bool is_valid_hostname(const std::string &hostname) {
    if (hostname.empty() || hostname.size() > 253) {
        return false;
    }
    return std::all_of(hostname.begin(), hostname.end(), [](char c) {
        return std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-';
    });
}

int safe_ping(const std::string &hostname) {
    if (!is_valid_hostname(hostname)) {
        std::cerr << "Invalid hostname" << std::endl;
        return 1;
    }

    pid_t pid = fork();
    if (pid == 0) {
        // Safe: execve with separate arguments, no shell involved
        const char *args[] = {"/usr/bin/ping", "-c", "3", hostname.c_str(), nullptr};
        const char *envp[] = {nullptr};
        execve("/usr/bin/ping",
               const_cast<char *const *>(args),
               const_cast<char *const *>(envp));
        perror("execve");
        _exit(1);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    }

    perror("fork");
    return 1;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <hostname>" << std::endl;
        return 1;
    }

    return safe_ping(argv[1]);
}
