// Safe: SSH command/path arguments are hardcoded or validated via allowlist,
// so no user-controlled data reaches libssh2/libssh sinks.
#include <libssh2.h>
#include <libssh/libssh.h>
#include <sys/stat.h>
#include <cstring>
#include <string>

static bool is_allowed_host(const char *host) {
    // allowlist check: only known internal hosts
    return std::strcmp(host, "db1.internal") == 0 || std::strcmp(host, "db2.internal") == 0;
}

void safe_libssh2_exec(LIBSSH2_CHANNEL *channel) {
    // Hardcoded command — no taint
    libssh2_channel_exec(channel, "uptime");
}

void safe_libssh_exec(ssh_channel channel) {
    // Hardcoded command — no taint
    ssh_channel_request_exec(channel, "/usr/local/bin/healthcheck --json");
}

void safe_scp_upload(LIBSSH2_SESSION *session) {
    // Hardcoded remote path
    libssh2_scp_send64(session, "/var/uploads/batch.tar.gz", 0644, 1024, 0, 0);
}

void safe_scp_download(LIBSSH2_SESSION *session) {
    // Hardcoded remote path
    struct stat sb;
    libssh2_scp_recv2(session, "/etc/motd", &sb);
}

void safe_ssh_tunnel(LIBSSH2_SESSION *session, const char *host) {
    // Allowlist check before tunneling
    if (!is_allowed_host(host)) {
        return;
    }
    libssh2_channel_direct_tcpip_ex(session, host, 80, "127.0.0.1", 1234);
}
