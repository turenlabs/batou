package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"

	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// C SFTP file-operation path-traversal tests (CWE-22)
// libssh2 (libssh2.org — libssh2_sftp_*) and libssh (libssh.org — sftp_*)
//
// Existing C SSH coverage already includes command-exec, SCP transfer, and
// SSH tunneling sinks (see tsflow_c_ssh_test.go). These tests cover the SFTP
// subsystem's remote file operations, which take a remote path the caller may
// not fully control — a classic path-traversal vector on the SFTP server.
// =========================================================================

// cSFTPSinkFired reports whether any flow ended at the given sink ID.
func cSFTPSinkFired(flows []taint.TaintFlow, sinkID string) bool {
	for _, f := range flows {
		if f.Sink.ID == sinkID {
			return true
		}
	}
	return false
}

func TestC_SFTP_PathTraversal_AllSinks(t *testing.T) {
	cases := []struct {
		name   string
		sinkID string
		cat    taint.SinkCategory
		code   string
	}{
		// --- libssh2 (libssh2_sftp_*) ---
		{
			name:   "libssh2_sftp_open",
			sinkID: "c.ssh.libssh2_sftp_open",
			cat:    taint.SnkFileRead,
			code: `
#include <libssh2_sftp.h>
#include <stdlib.h>
void op(LIBSSH2_SFTP *sftp) {
    char *path = getenv("REMOTE_PATH");
    libssh2_sftp_open(sftp, path, 0, 0);
}
`,
		},
		{
			name:   "libssh2_sftp_open_ex",
			sinkID: "c.ssh.libssh2_sftp_open",
			cat:    taint.SnkFileRead,
			code: `
#include <libssh2_sftp.h>
#include <string.h>
#include <stdlib.h>
void op(LIBSSH2_SFTP *sftp) {
    char *path = getenv("REMOTE_PATH");
    libssh2_sftp_open_ex(sftp, path, strlen(path), 0, 0, 0);
}
`,
		},
		{
			name:   "libssh2_sftp_opendir",
			sinkID: "c.ssh.libssh2_sftp_open",
			cat:    taint.SnkFileRead,
			code: `
#include <libssh2_sftp.h>
#include <stdlib.h>
void op(LIBSSH2_SFTP *sftp) {
    char *path = getenv("REMOTE_DIR");
    libssh2_sftp_opendir(sftp, path);
}
`,
		},
		{
			name:   "libssh2_sftp_unlink",
			sinkID: "c.ssh.libssh2_sftp_unlink",
			cat:    taint.SnkFileWrite,
			code: `
#include <libssh2_sftp.h>
#include <stdlib.h>
void op(LIBSSH2_SFTP *sftp) {
    char *path = getenv("REMOTE_PATH");
    libssh2_sftp_unlink(sftp, path);
}
`,
		},
		{
			name:   "libssh2_sftp_mkdir",
			sinkID: "c.ssh.libssh2_sftp_mkdir",
			cat:    taint.SnkFileWrite,
			code: `
#include <libssh2_sftp.h>
#include <stdlib.h>
void op(LIBSSH2_SFTP *sftp) {
    char *path = getenv("REMOTE_DIR");
    libssh2_sftp_mkdir(sftp, path, 0755);
}
`,
		},
		{
			name:   "libssh2_sftp_rmdir",
			sinkID: "c.ssh.libssh2_sftp_rmdir",
			cat:    taint.SnkFileWrite,
			code: `
#include <libssh2_sftp.h>
#include <stdlib.h>
void op(LIBSSH2_SFTP *sftp) {
    char *path = getenv("REMOTE_DIR");
    libssh2_sftp_rmdir(sftp, path);
}
`,
		},
		{
			name:   "libssh2_sftp_rename_dest_tainted",
			sinkID: "c.ssh.libssh2_sftp_rename",
			cat:    taint.SnkFileWrite,
			code: `
#include <libssh2_sftp.h>
#include <stdlib.h>
void op(LIBSSH2_SFTP *sftp) {
    char *dst = getenv("REMOTE_DEST");
    libssh2_sftp_rename(sftp, "/tmp/src", dst);
}
`,
		},
		{
			name:   "libssh2_sftp_stat",
			sinkID: "c.ssh.libssh2_sftp_stat",
			cat:    taint.SnkFileRead,
			code: `
#include <libssh2_sftp.h>
#include <stdlib.h>
void op(LIBSSH2_SFTP *sftp) {
    char *path = getenv("REMOTE_PATH");
    LIBSSH2_SFTP_ATTRIBUTES attrs;
    libssh2_sftp_stat(sftp, path, &attrs);
}
`,
		},
		{
			name:   "libssh2_sftp_lstat",
			sinkID: "c.ssh.libssh2_sftp_stat",
			cat:    taint.SnkFileRead,
			code: `
#include <libssh2_sftp.h>
#include <stdlib.h>
void op(LIBSSH2_SFTP *sftp) {
    char *path = getenv("REMOTE_PATH");
    LIBSSH2_SFTP_ATTRIBUTES attrs;
    libssh2_sftp_lstat(sftp, path, &attrs);
}
`,
		},
		{
			name:   "libssh2_sftp_symlink",
			sinkID: "c.ssh.libssh2_sftp_symlink",
			cat:    taint.SnkFileWrite,
			code: `
#include <libssh2_sftp.h>
#include <stdlib.h>
void op(LIBSSH2_SFTP *sftp) {
    char *link = getenv("REMOTE_LINK");
    libssh2_sftp_symlink(sftp, "/tmp/target", link);
}
`,
		},
		{
			name:   "libssh2_sftp_realpath",
			sinkID: "c.ssh.libssh2_sftp_realpath",
			cat:    taint.SnkFileRead,
			code: `
#include <libssh2_sftp.h>
#include <stdlib.h>
void op(LIBSSH2_SFTP *sftp) {
    char *path = getenv("REMOTE_PATH");
    char buf[512];
    libssh2_sftp_realpath(sftp, path, buf, sizeof(buf));
}
`,
		},
		{
			name:   "libssh2_sftp_readlink",
			sinkID: "c.ssh.libssh2_sftp_realpath",
			cat:    taint.SnkFileRead,
			code: `
#include <libssh2_sftp.h>
#include <stdlib.h>
void op(LIBSSH2_SFTP *sftp) {
    char *path = getenv("REMOTE_PATH");
    char buf[512];
    libssh2_sftp_readlink(sftp, path, buf, sizeof(buf));
}
`,
		},
		// --- libssh (sftp_*) ---
		{
			name:   "sftp_open",
			sinkID: "c.ssh.sftp_open",
			cat:    taint.SnkFileRead,
			code: `
#include <libssh/sftp.h>
#include <stdlib.h>
void op(sftp_session sftp) {
    char *path = getenv("REMOTE_PATH");
    sftp_open(sftp, path, 0, 0);
}
`,
		},
		{
			name:   "sftp_opendir",
			sinkID: "c.ssh.sftp_open",
			cat:    taint.SnkFileRead,
			code: `
#include <libssh/sftp.h>
#include <stdlib.h>
void op(sftp_session sftp) {
    char *path = getenv("REMOTE_DIR");
    sftp_opendir(sftp, path);
}
`,
		},
		{
			name:   "sftp_unlink",
			sinkID: "c.ssh.sftp_unlink",
			cat:    taint.SnkFileWrite,
			code: `
#include <libssh/sftp.h>
#include <stdlib.h>
void op(sftp_session sftp) {
    char *path = getenv("REMOTE_PATH");
    sftp_unlink(sftp, path);
}
`,
		},
		{
			name:   "sftp_mkdir",
			sinkID: "c.ssh.sftp_mkdir",
			cat:    taint.SnkFileWrite,
			code: `
#include <libssh/sftp.h>
#include <stdlib.h>
void op(sftp_session sftp) {
    char *path = getenv("REMOTE_DIR");
    sftp_mkdir(sftp, path, 0755);
}
`,
		},
		{
			name:   "sftp_rmdir",
			sinkID: "c.ssh.sftp_rmdir",
			cat:    taint.SnkFileWrite,
			code: `
#include <libssh/sftp.h>
#include <stdlib.h>
void op(sftp_session sftp) {
    char *path = getenv("REMOTE_DIR");
    sftp_rmdir(sftp, path);
}
`,
		},
		{
			name:   "sftp_rename_dest_tainted",
			sinkID: "c.ssh.sftp_rename",
			cat:    taint.SnkFileWrite,
			code: `
#include <libssh/sftp.h>
#include <stdlib.h>
void op(sftp_session sftp) {
    char *dst = getenv("REMOTE_DEST");
    sftp_rename(sftp, "/tmp/src", dst);
}
`,
		},
		{
			name:   "sftp_stat",
			sinkID: "c.ssh.sftp_stat",
			cat:    taint.SnkFileRead,
			code: `
#include <libssh/sftp.h>
#include <stdlib.h>
void op(sftp_session sftp) {
    char *path = getenv("REMOTE_PATH");
    sftp_stat(sftp, path);
}
`,
		},
		{
			name:   "sftp_symlink",
			sinkID: "c.ssh.sftp_symlink",
			cat:    taint.SnkFileWrite,
			code: `
#include <libssh/sftp.h>
#include <stdlib.h>
void op(sftp_session sftp) {
    char *target = getenv("REMOTE_TARGET");
    sftp_symlink(sftp, target, "/tmp/dest");
}
`,
		},
		{
			name:   "sftp_hardlink",
			sinkID: "c.ssh.sftp_symlink",
			cat:    taint.SnkFileWrite,
			code: `
#include <libssh/sftp.h>
#include <stdlib.h>
void op(sftp_session sftp) {
    char *old = getenv("REMOTE_OLD");
    sftp_hardlink(sftp, old, "/tmp/new");
}
`,
		},
		{
			name:   "sftp_readlink",
			sinkID: "c.ssh.sftp_readlink",
			cat:    taint.SnkFileRead,
			code: `
#include <libssh/sftp.h>
#include <stdlib.h>
void op(sftp_session sftp) {
    char *path = getenv("REMOTE_PATH");
    sftp_readlink(sftp, path);
}
`,
		},
		{
			name:   "sftp_canonicalize_path",
			sinkID: "c.ssh.sftp_readlink",
			cat:    taint.SnkFileRead,
			code: `
#include <libssh/sftp.h>
#include <stdlib.h>
void op(sftp_session sftp) {
    char *path = getenv("REMOTE_PATH");
    sftp_canonicalize_path(sftp, path);
}
`,
		},
		{
			name:   "sftp_chmod",
			sinkID: "c.ssh.sftp_chmod",
			cat:    taint.SnkFileWrite,
			code: `
#include <libssh/sftp.h>
#include <stdlib.h>
void op(sftp_session sftp) {
    char *path = getenv("REMOTE_PATH");
    sftp_chmod(sftp, path, 0644);
}
`,
		},
		{
			name:   "sftp_chown",
			sinkID: "c.ssh.sftp_chmod",
			cat:    taint.SnkFileWrite,
			code: `
#include <libssh/sftp.h>
#include <stdlib.h>
void op(sftp_session sftp) {
    char *path = getenv("REMOTE_PATH");
    sftp_chown(sftp, path, 0, 0);
}
`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flows := Analyze(tc.code, "/app/sftp_"+tc.name+".c", rules.LangC)
			if !hasTaintFlow(flows, tc.cat) {
				t.Errorf("expected %s flow for getenv -> %s", tc.cat, tc.name)
			}
			if !cSFTPSinkFired(flows, tc.sinkID) {
				t.Errorf("expected sink %s to fire for %s", tc.sinkID, tc.name)
				for _, f := range flows {
					t.Logf("  flow: %s -> %s (sink=%s, conf %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
				}
			}
		})
	}
}

func TestC_SFTP_NoFlow_ConstantPath(t *testing.T) {
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
			flows := Analyze(tc.code, "/app/"+tc.name+".c", rules.LangC)
			if hasTaintFlow(flows, taint.SnkFileWrite) || hasTaintFlow(flows, taint.SnkFileRead) {
				t.Errorf("expected no path-traversal flow for constant remote path in %s", tc.name)
				for _, f := range flows {
					t.Logf("  flow: %s -> %s (sink=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
				}
			}
		})
	}
}

func TestC_SFTP_SinksRegistered(t *testing.T) {
	want := []string{
		"c.ssh.libssh2_sftp_open",
		"c.ssh.libssh2_sftp_unlink",
		"c.ssh.libssh2_sftp_mkdir",
		"c.ssh.libssh2_sftp_rmdir",
		"c.ssh.libssh2_sftp_rename",
		"c.ssh.libssh2_sftp_stat",
		"c.ssh.libssh2_sftp_symlink",
		"c.ssh.libssh2_sftp_realpath",
		"c.ssh.sftp_open",
		"c.ssh.sftp_unlink",
		"c.ssh.sftp_mkdir",
		"c.ssh.sftp_rmdir",
		"c.ssh.sftp_rename",
		"c.ssh.sftp_stat",
		"c.ssh.sftp_symlink",
		"c.ssh.sftp_readlink",
		"c.ssh.sftp_chmod",
	}
	byID := map[string]taint.SinkDef{}
	for _, s := range taint.SinksForLanguage(rules.LangC) {
		byID[s.ID] = s
	}
	for _, id := range want {
		s, ok := byID[id]
		if !ok {
			t.Errorf("sink %s not registered for C", id)
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
