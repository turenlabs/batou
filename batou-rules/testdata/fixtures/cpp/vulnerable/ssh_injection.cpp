// Vulnerable: libssh2 / libssh SSH command injection, SCP path traversal, SSH tunnel SSRF
#include <libssh2.h>
#include <libssh/libssh.h>
#include <sys/stat.h>
#include <cstdlib>
#include <cstring>

void vuln_libssh2_exec(LIBSSH2_CHANNEL *channel) {
    // CWE-78: remote command is built from env var
    char *cmd = std::getenv("REMOTE_CMD");
    libssh2_channel_exec(channel, cmd);
}

void vuln_libssh2_startup(LIBSSH2_CHANNEL *channel) {
    // CWE-78: message argument is tainted
    char *msg = std::getenv("SSH_MSG");
    libssh2_channel_process_startup(channel, "exec", 4, msg, std::strlen(msg));
}

void vuln_libssh_exec(ssh_channel channel) {
    // CWE-78: libssh command injection
    char *cmd = std::getenv("REMOTE_CMD");
    ssh_channel_request_exec(channel, cmd);
}

void vuln_scp_upload(LIBSSH2_SESSION *session) {
    // CWE-22: remote SCP path from user
    char *path = std::getenv("REMOTE_PATH");
    libssh2_scp_send64(session, path, 0644, 1024, 0, 0);
}

void vuln_scp_download(LIBSSH2_SESSION *session) {
    // CWE-22: remote SCP download path from user
    char *path = std::getenv("REMOTE_PATH");
    struct stat sb;
    libssh2_scp_recv2(session, path, &sb);
}

void vuln_ssh_tunnel(LIBSSH2_SESSION *session) {
    // CWE-918: tunnel destination from user input (SSH-based SSRF)
    char *host = std::getenv("DEST_HOST");
    libssh2_channel_direct_tcpip_ex(session, host, 80, "127.0.0.1", 1234);
}

void vuln_libssh_forward(ssh_channel channel) {
    // CWE-918: libssh tunnel destination from user input
    char *host = std::getenv("DEST_HOST");
    ssh_channel_open_forward(channel, host, 80, "localhost", 1234);
}
