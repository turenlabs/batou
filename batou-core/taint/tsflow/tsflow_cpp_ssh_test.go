package tsflow

import (
	"testing"

	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// C++ SSH command execution + SCP file transfer tests
// libssh2 (libssh2.org) and libssh (libssh.org) used from C++ sources
// =========================================================================

func TestCPP_Libssh2ChannelExec_CommandInjection(t *testing.T) {
	code := `
#include <libssh2.h>
#include <cstdlib>

void run_remote(LIBSSH2_CHANNEL *channel) {
    char *cmd = std::getenv("REMOTE_CMD");
    libssh2_channel_exec(channel, cmd);
}
`
	flows := Analyze(code, "/app/ssh_exec.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for getenv -> libssh2_channel_exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Libssh2ChannelProcessStartup_CommandInjection(t *testing.T) {
	code := `
#include <libssh2.h>
#include <cstring>
#include <cstdlib>

void run_startup(LIBSSH2_CHANNEL *channel) {
    char *msg = std::getenv("SSH_MSG");
    libssh2_channel_process_startup(channel, "exec", 4, msg, std::strlen(msg));
}
`
	flows := Analyze(code, "/app/ssh_startup.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for getenv -> libssh2_channel_process_startup")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Libssh2ChannelSubsystem_CommandInjection(t *testing.T) {
	code := `
#include <libssh2.h>
#include <cstdlib>

void request_subsystem(LIBSSH2_CHANNEL *channel) {
    char *sub = std::getenv("SUBSYSTEM");
    libssh2_channel_subsystem(channel, sub);
}
`
	flows := Analyze(code, "/app/ssh_subsystem.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for getenv -> libssh2_channel_subsystem")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_SshChannelRequestExec_CommandInjection(t *testing.T) {
	code := `
#include <libssh/libssh.h>
#include <cstdlib>

void run_remote_libssh(ssh_channel channel) {
    char *cmd = std::getenv("REMOTE_CMD");
    ssh_channel_request_exec(channel, cmd);
}
`
	flows := Analyze(code, "/app/libssh_exec.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for getenv -> ssh_channel_request_exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_SshChannelRequestSubsystem_CommandInjection(t *testing.T) {
	code := `
#include <libssh/libssh.h>
#include <cstdlib>

void request_sub_libssh(ssh_channel channel) {
    char *sub = std::getenv("SUBSYSTEM");
    ssh_channel_request_subsystem(channel, sub);
}
`
	flows := Analyze(code, "/app/libssh_sub.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for getenv -> ssh_channel_request_subsystem")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Libssh2ScpSend_PathTraversal(t *testing.T) {
	code := `
#include <libssh2.h>
#include <cstdlib>

void upload_file(LIBSSH2_SESSION *session) {
    char *path = std::getenv("REMOTE_PATH");
    libssh2_scp_send64(session, path, 0644, 1024, 0, 0);
}
`
	flows := Analyze(code, "/app/scp_send.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected path traversal flow for getenv -> libssh2_scp_send64")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Libssh2ScpRecv_PathTraversal(t *testing.T) {
	code := `
#include <libssh2.h>
#include <sys/stat.h>
#include <cstdlib>

void download_file(LIBSSH2_SESSION *session) {
    char *path = std::getenv("REMOTE_PATH");
    struct stat sb;
    libssh2_scp_recv2(session, path, &sb);
}
`
	flows := Analyze(code, "/app/scp_recv.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected path traversal flow for getenv -> libssh2_scp_recv2")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_SshScpPushFile_PathTraversal(t *testing.T) {
	code := `
#include <libssh/libssh.h>
#include <cstdlib>

void push_libssh(ssh_scp scp) {
    char *filename = std::getenv("UPLOAD_PATH");
    ssh_scp_push_file(scp, filename, 1024, 0644);
}
`
	flows := Analyze(code, "/app/libssh_push.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected path traversal flow for getenv -> ssh_scp_push_file")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Libssh2DirectTcpip_SSRF(t *testing.T) {
	code := `
#include <libssh2.h>
#include <cstdlib>

void open_tunnel(LIBSSH2_SESSION *session) {
    char *host = std::getenv("DEST_HOST");
    libssh2_channel_direct_tcpip_ex(session, host, 80, "127.0.0.1", 1234);
}
`
	flows := Analyze(code, "/app/ssh_tunnel.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for getenv -> libssh2_channel_direct_tcpip_ex")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_SshChannelOpenForward_SSRF(t *testing.T) {
	code := `
#include <libssh/libssh.h>
#include <cstdlib>

void forward_libssh(ssh_channel channel) {
    char *host = std::getenv("DEST_HOST");
    ssh_channel_open_forward(channel, host, 80, "localhost", 1234);
}
`
	flows := Analyze(code, "/app/libssh_forward.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for getenv -> ssh_channel_open_forward")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
