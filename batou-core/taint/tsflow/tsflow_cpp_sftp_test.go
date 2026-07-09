package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"

	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// C++ SFTP file-operation path-traversal tests (CWE-22)
// libssh2 (libssh2.org — libssh2_sftp_*) and libssh (libssh.org — sftp_*)
// used from C++ sources.
//
// Existing C++ SSH coverage already includes command-exec, SCP transfer, and
// SSH tunneling sinks (see tsflow_cpp_ssh_test.go). These tests cover the SFTP
// subsystem's remote file operations, which take a remote path the caller may
// not fully control — a classic path-traversal vector on the SFTP server.
// Mirrors tsflow_c_sftp_test.go (same C library APIs called from C++).
// =========================================================================

// cppSFTPSinkFired reports whether any flow ended at the given sink ID.
func cppSFTPSinkFired(flows []taint.TaintFlow, sinkID string) bool {
	for _, f := range flows {
		if f.Sink.ID == sinkID {
			return true
		}
	}
	return false
}

func TestCPP_SFTP_PathTraversal_AllSinks(t *testing.T) {
	cases := []struct {
		name   string
		sinkID string
		cat    taint.SinkCategory
		code   string
	}{
		// --- libssh2 (libssh2_sftp_*) ---
		{
			name:   "libssh2_sftp_open",
			sinkID: "cpp.ssh.libssh2_sftp_open",
			cat:    taint.SnkFileRead,
			code: `
#include <libssh2_sftp.h>
#include <cstdlib>
void op(LIBSSH2_SFTP *sftp) {
    char *path = std::getenv("REMOTE_PATH");
    libssh2_sftp_open(sftp, path, 0, 0);
}
`,
		},
		{
			name:   "libssh2_sftp_open_ex",
			sinkID: "cpp.ssh.libssh2_sftp_open",
			cat:    taint.SnkFileRead,
			code: `
#include <libssh2_sftp.h>
#include <cstring>
#include <cstdlib>
void op(LIBSSH2_SFTP *sftp) {
    char *path = std::getenv("REMOTE_PATH");
    libssh2_sftp_open_ex(sftp, path, std::strlen(path), 0, 0, 0);
}
`,
		},
		{
			name:   "libssh2_sftp_opendir",
			sinkID: "cpp.ssh.libssh2_sftp_open",
			cat:    taint.SnkFileRead,
			code: `
#include <libssh2_sftp.h>
#include <cstdlib>
void op(LIBSSH2_SFTP *sftp) {
    char *path = std::getenv("REMOTE_DIR");
    libssh2_sftp_opendir(sftp, path);
}
`,
		},
		{
			name:   "libssh2_sftp_unlink",
			sinkID: "cpp.ssh.libssh2_sftp_unlink",
			cat:    taint.SnkFileWrite,
			code: `
#include <libssh2_sftp.h>
#include <cstdlib>
void op(LIBSSH2_SFTP *sftp) {
    char *path = std::getenv("REMOTE_PATH");
    libssh2_sftp_unlink(sftp, path);
}
`,
		},
		{
			name:   "libssh2_sftp_mkdir",
			sinkID: "cpp.ssh.libssh2_sftp_mkdir",
			cat:    taint.SnkFileWrite,
			code: `
#include <libssh2_sftp.h>
#include <cstdlib>
void op(LIBSSH2_SFTP *sftp) {
    char *path = std::getenv("REMOTE_DIR");
    libssh2_sftp_mkdir(sftp, path, 0755);
}
`,
		},
		{
			name:   "libssh2_sftp_rmdir",
			sinkID: "cpp.ssh.libssh2_sftp_rmdir",
			cat:    taint.SnkFileWrite,
			code: `
#include <libssh2_sftp.h>
#include <cstdlib>
void op(LIBSSH2_SFTP *sftp) {
    char *path = std::getenv("REMOTE_DIR");
    libssh2_sftp_rmdir(sftp, path);
}
`,
		},
		{
			name:   "libssh2_sftp_rename_dest_tainted",
			sinkID: "cpp.ssh.libssh2_sftp_rename",
			cat:    taint.SnkFileWrite,
			code: `
#include <libssh2_sftp.h>
#include <cstdlib>
void op(LIBSSH2_SFTP *sftp) {
    char *dst = std::getenv("REMOTE_DEST");
    libssh2_sftp_rename(sftp, "/tmp/src", dst);
}
`,
		},
		{
			name:   "libssh2_sftp_stat",
			sinkID: "cpp.ssh.libssh2_sftp_stat",
			cat:    taint.SnkFileRead,
			code: `
#include <libssh2_sftp.h>
#include <cstdlib>
void op(LIBSSH2_SFTP *sftp) {
    char *path = std::getenv("REMOTE_PATH");
    LIBSSH2_SFTP_ATTRIBUTES attrs;
    libssh2_sftp_stat(sftp, path, &attrs);
}
`,
		},
		{
			name:   "libssh2_sftp_lstat",
			sinkID: "cpp.ssh.libssh2_sftp_stat",
			cat:    taint.SnkFileRead,
			code: `
#include <libssh2_sftp.h>
#include <cstdlib>
void op(LIBSSH2_SFTP *sftp) {
    char *path = std::getenv("REMOTE_PATH");
    LIBSSH2_SFTP_ATTRIBUTES attrs;
    libssh2_sftp_lstat(sftp, path, &attrs);
}
`,
		},
		{
			name:   "libssh2_sftp_symlink",
			sinkID: "cpp.ssh.libssh2_sftp_symlink",
			cat:    taint.SnkFileWrite,
			code: `
#include <libssh2_sftp.h>
#include <cstdlib>
void op(LIBSSH2_SFTP *sftp) {
    char *link = std::getenv("REMOTE_LINK");
    libssh2_sftp_symlink(sftp, "/tmp/target", link);
}
`,
		},
		{
			name:   "libssh2_sftp_realpath",
			sinkID: "cpp.ssh.libssh2_sftp_realpath",
			cat:    taint.SnkFileRead,
			code: `
#include <libssh2_sftp.h>
#include <cstdlib>
void op(LIBSSH2_SFTP *sftp) {
    char *path = std::getenv("REMOTE_PATH");
    char buf[512];
    libssh2_sftp_realpath(sftp, path, buf, sizeof(buf));
}
`,
		},
		{
			name:   "libssh2_sftp_readlink",
			sinkID: "cpp.ssh.libssh2_sftp_realpath",
			cat:    taint.SnkFileRead,
			code: `
#include <libssh2_sftp.h>
#include <cstdlib>
void op(LIBSSH2_SFTP *sftp) {
    char *path = std::getenv("REMOTE_PATH");
    char buf[512];
    libssh2_sftp_readlink(sftp, path, buf, sizeof(buf));
}
`,
		},
		// --- libssh (sftp_*) ---
		{
			name:   "sftp_open",
			sinkID: "cpp.ssh.sftp_open",
			cat:    taint.SnkFileRead,
			code: `
#include <libssh/sftp.h>
#include <cstdlib>
void op(sftp_session sftp) {
    char *path = std::getenv("REMOTE_PATH");
    sftp_open(sftp, path, 0, 0);
}
`,
		},
		{
			name:   "sftp_opendir",
			sinkID: "cpp.ssh.sftp_open",
			cat:    taint.SnkFileRead,
			code: `
#include <libssh/sftp.h>
#include <cstdlib>
void op(sftp_session sftp) {
    char *path = std::getenv("REMOTE_DIR");
    sftp_opendir(sftp, path);
}
`,
		},
		{
			name:   "sftp_unlink",
			sinkID: "cpp.ssh.sftp_unlink",
			cat:    taint.SnkFileWrite,
			code: `
#include <libssh/sftp.h>
#include <cstdlib>
void op(sftp_session sftp) {
    char *path = std::getenv("REMOTE_PATH");
    sftp_unlink(sftp, path);
}
`,
		},
		{
			name:   "sftp_mkdir",
			sinkID: "cpp.ssh.sftp_mkdir",
			cat:    taint.SnkFileWrite,
			code: `
#include <libssh/sftp.h>
#include <cstdlib>
void op(sftp_session sftp) {
    char *path = std::getenv("REMOTE_DIR");
    sftp_mkdir(sftp, path, 0755);
}
`,
		},
		{
			name:   "sftp_rmdir",
			sinkID: "cpp.ssh.sftp_rmdir",
			cat:    taint.SnkFileWrite,
			code: `
#include <libssh/sftp.h>
#include <cstdlib>
void op(sftp_session sftp) {
    char *path = std::getenv("REMOTE_DIR");
    sftp_rmdir(sftp, path);
}
`,
		},
		{
			name:   "sftp_rename_dest_tainted",
			sinkID: "cpp.ssh.sftp_rename",
			cat:    taint.SnkFileWrite,
			code: `
#include <libssh/sftp.h>
#include <cstdlib>
void op(sftp_session sftp) {
    char *dst = std::getenv("REMOTE_DEST");
    sftp_rename(sftp, "/tmp/src", dst);
}
`,
		},
		{
			name:   "sftp_stat",
			sinkID: "cpp.ssh.sftp_stat",
			cat:    taint.SnkFileRead,
			code: `
#include <libssh/sftp.h>
#include <cstdlib>
void op(sftp_session sftp) {
    char *path = std::getenv("REMOTE_PATH");
    sftp_stat(sftp, path);
}
`,
		},
		{
			name:   "sftp_symlink",
			sinkID: "cpp.ssh.sftp_symlink",
			cat:    taint.SnkFileWrite,
			code: `
#include <libssh/sftp.h>
#include <cstdlib>
void op(sftp_session sftp) {
    char *target = std::getenv("REMOTE_TARGET");
    sftp_symlink(sftp, target, "/tmp/dest");
}
`,
		},
		{
			name:   "sftp_hardlink",
			sinkID: "cpp.ssh.sftp_symlink",
			cat:    taint.SnkFileWrite,
			code: `
#include <libssh/sftp.h>
#include <cstdlib>
void op(sftp_session sftp) {
    char *old = std::getenv("REMOTE_OLD");
    sftp_hardlink(sftp, old, "/tmp/new");
}
`,
		},
		{
			name:   "sftp_readlink",
			sinkID: "cpp.ssh.sftp_readlink",
			cat:    taint.SnkFileRead,
			code: `
#include <libssh/sftp.h>
#include <cstdlib>
void op(sftp_session sftp) {
    char *path = std::getenv("REMOTE_PATH");
    sftp_readlink(sftp, path);
}
`,
		},
		{
			name:   "sftp_canonicalize_path",
			sinkID: "cpp.ssh.sftp_readlink",
			cat:    taint.SnkFileRead,
			code: `
#include <libssh/sftp.h>
#include <cstdlib>
void op(sftp_session sftp) {
    char *path = std::getenv("REMOTE_PATH");
    sftp_canonicalize_path(sftp, path);
}
`,
		},
		{
			name:   "sftp_chmod",
			sinkID: "cpp.ssh.sftp_chmod",
			cat:    taint.SnkFileWrite,
			code: `
#include <libssh/sftp.h>
#include <cstdlib>
void op(sftp_session sftp) {
    char *path = std::getenv("REMOTE_PATH");
    sftp_chmod(sftp, path, 0644);
}
`,
		},
		{
			name:   "sftp_chown",
			sinkID: "cpp.ssh.sftp_chmod",
			cat:    taint.SnkFileWrite,
			code: `
#include <libssh/sftp.h>
#include <cstdlib>
void op(sftp_session sftp) {
    char *path = std::getenv("REMOTE_PATH");
    sftp_chown(sftp, path, 0, 0);
}
`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flows := Analyze(tc.code, "/app/sftp_"+tc.name+".cpp", rules.LangCPP)
			if !hasTaintFlow(flows, tc.cat) {
				t.Errorf("expected %s flow for getenv -> %s", tc.cat, tc.name)
			}
			if !cppSFTPSinkFired(flows, tc.sinkID) {
				t.Errorf("expected sink %s to fire for %s", tc.sinkID, tc.name)
				for _, f := range flows {
					t.Logf("  flow: %s -> %s (sink=%s, conf %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
				}
			}
		})
	}
}

func TestCPP_SFTP_NoFlow_ConstantPath(t *testing.T) {
	cases := []struct {
		name string
		code string
	}{
		{
			name: "libssh2_sftp_unlink_constant",
			code: `
#include <libssh2_sftp.h>
void op(LIBSSH2_SFTP *sftp) {
    libssh2_sftp_unlink(sftp, "/var/spool/app/fixed.tmp");
}
`,
		},
		{
			name: "sftp_mkdir_constant",
			code: `
#include <libssh/sftp.h>
void op(sftp_session sftp) {
    sftp_mkdir(sftp, "/srv/data/uploads", 0755);
}
`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flows := Analyze(tc.code, "/app/"+tc.name+".cpp", rules.LangCPP)
			if hasTaintFlow(flows, taint.SnkFileWrite) || hasTaintFlow(flows, taint.SnkFileRead) {
				t.Errorf("expected no path-traversal flow for constant remote path in %s", tc.name)
				for _, f := range flows {
					t.Logf("  flow: %s -> %s (sink=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
				}
			}
		})
	}
}

func TestCPP_SFTP_SinksRegistered(t *testing.T) {
	want := []string{
		"cpp.ssh.libssh2_sftp_open",
		"cpp.ssh.libssh2_sftp_unlink",
		"cpp.ssh.libssh2_sftp_mkdir",
		"cpp.ssh.libssh2_sftp_rmdir",
		"cpp.ssh.libssh2_sftp_rename",
		"cpp.ssh.libssh2_sftp_stat",
		"cpp.ssh.libssh2_sftp_symlink",
		"cpp.ssh.libssh2_sftp_realpath",
		"cpp.ssh.sftp_open",
		"cpp.ssh.sftp_unlink",
		"cpp.ssh.sftp_mkdir",
		"cpp.ssh.sftp_rmdir",
		"cpp.ssh.sftp_rename",
		"cpp.ssh.sftp_stat",
		"cpp.ssh.sftp_symlink",
		"cpp.ssh.sftp_readlink",
		"cpp.ssh.sftp_chmod",
	}
	byID := map[string]taint.SinkDef{}
	for _, s := range taint.SinksForLanguage(rules.LangCPP) {
		byID[s.ID] = s
	}
	for _, id := range want {
		s, ok := byID[id]
		if !ok {
			t.Errorf("sink %s not registered for C++", id)
			continue
		}
		if s.CWEID != "CWE-22" {
			t.Errorf("sink %s: expected CWE-22, got %q", id, s.CWEID)
		}
		if s.Category != taint.SnkFileRead && s.Category != taint.SnkFileWrite {
			t.Errorf("sink %s: expected file read/write category, got %q", id, s.Category)
		}
		if len(s.DangerousArgs) == 0 {
			t.Errorf("sink %s: expected non-empty DangerousArgs", id)
		}
	}
}
