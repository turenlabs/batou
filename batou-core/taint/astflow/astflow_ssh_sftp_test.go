package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Go SSH / SFTP remote-operation sinks
//
//   * golang.org/x/crypto/ssh — (*ssh.Session).{Run,Start,Output,CombinedOutput}
//     run their string argument as a command on the remote host (CWE-78).
//   * github.com/pkg/sftp — (*sftp.Client) methods take a remote path as their
//     first argument; a tainted path is remote path traversal (CWE-22).
//
// The *ssh.Session value is almost always a `:=` local from client.NewSession(),
// so astflow has no static type for it — matchesReceiverType() resolves the
// "session"/"sess" receiver names. *sftp.Client values are commonly statically
// typed (function parameters), in which case typeEnv attributes the precise
// rule ID; the untyped form is still caught by the generic go.os.* file sinks.
// =========================================================================

func TestCatalogMatcher_SSHSFTPSinksRegistered(t *testing.T) {
	cat := taint.GetCatalog("go")
	if cat == nil {
		t.Fatal("Go catalog not registered")
	}
	matcher := NewCatalogMatcher(nil, cat.Sinks(), nil, nil)

	want := map[string][]string{
		"Run":             {"go.ssh.session.run"},
		"Start":           {"go.ssh.session.start"},
		"Output":          {"go.ssh.session.output"},
		"CombinedOutput":  {"go.ssh.session.combinedoutput"},
		"Open":            {"go.sftp.client.open"},
		"OpenFile":        {"go.sftp.client.openfile"},
		"Create":          {"go.sftp.client.create"},
		"Remove":          {"go.sftp.client.remove"},
		"RemoveDirectory": {"go.sftp.client.remove"},
		"Mkdir":           {"go.sftp.client.mkdir"},
		"MkdirAll":        {"go.sftp.client.mkdir"},
		"Rename":          {"go.sftp.client.rename"},
		"PosixRename":     {"go.sftp.client.rename"},
		"Symlink":         {"go.sftp.client.symlink"},
		"Link":            {"go.sftp.client.symlink"},
		"ReadDir":         {"go.sftp.client.readdir"},
	}
	for method, ids := range want {
		got := map[string]bool{}
		for _, s := range matcher.sinksByMethod[method] {
			got[s.ID] = true
		}
		for _, id := range ids {
			if !got[id] {
				t.Errorf("expected sink %q to be indexed under method %q", id, method)
			}
		}
	}
}

// --- SSH remote command execution (CWE-78) ---

// Untyped *ssh.Session local from client.NewSession() — exercises the
// matchesReceiverType("session", "*ssh.Session") heuristic. Without that
// heuristic (and the go.ssh.session.run sink) this flow is not detected.
func TestAnalyzeGo_SSH_SessionRun_CommandInjection(t *testing.T) {
	code := `package main

import (
	"net/http"

	"golang.org/x/crypto/ssh"
)

func handler(w http.ResponseWriter, r *http.Request, client *ssh.Client) {
	cmd := r.URL.Query().Get("cmd")
	session, err := client.NewSession()
	if err != nil {
		return
	}
	defer session.Close()
	_ = session.Run(cmd)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Fatalf("expected SnkCommand flow for r.URL.Query().Get -> session.Run, got %d flows", len(flows))
	}
	if !hasSinkID(flows, "go.ssh.session.run") {
		t.Errorf("expected the flow to be attributed to go.ssh.session.run")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_SSH_SessionStart_CommandInjection(t *testing.T) {
	code := `package main

import (
	"net/http"

	"golang.org/x/crypto/ssh"
)

func handler(w http.ResponseWriter, r *http.Request, client *ssh.Client) {
	cmd := r.FormValue("cmd")
	sess, err := client.NewSession()
	if err != nil {
		return
	}
	_ = sess.Start(cmd)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasSinkID(flows, "go.ssh.session.start") {
		t.Errorf("expected SnkCommand flow attributed to go.ssh.session.start, got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_SSH_SessionOutput_CommandInjection(t *testing.T) {
	code := `package main

import (
	"net/http"

	"golang.org/x/crypto/ssh"
)

func handler(w http.ResponseWriter, r *http.Request, client *ssh.Client) {
	cmd := r.Header.Get("X-Cmd")
	session, err := client.NewSession()
	if err != nil {
		return
	}
	out, _ := session.Output(cmd)
	_ = out
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasSinkID(flows, "go.ssh.session.output") {
		t.Errorf("expected SnkCommand flow attributed to go.ssh.session.output, got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// Statically-typed *ssh.Session parameter — exercises the typeEnv attribution path.
func TestAnalyzeGo_SSH_SessionCombinedOutput_TypedParam(t *testing.T) {
	code := `package main

import (
	"net/http"

	"golang.org/x/crypto/ssh"
)

func runRemote(session *ssh.Session, cmd string) ([]byte, error) {
	return session.CombinedOutput(cmd)
}

func handler(w http.ResponseWriter, r *http.Request, session *ssh.Session) {
	cmd := r.URL.Query().Get("cmd")
	_, _ = session.CombinedOutput(cmd)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasSinkID(flows, "go.ssh.session.combinedoutput") {
		t.Errorf("expected SnkCommand flow attributed to go.ssh.session.combinedoutput, got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// Negative: a constant command string must not produce a flow.
func TestAnalyzeGo_SSH_SessionRun_ConstantCommand_NoFlow(t *testing.T) {
	code := `package main

import (
	"net/http"

	"golang.org/x/crypto/ssh"
)

func handler(w http.ResponseWriter, r *http.Request, client *ssh.Client) {
	session, err := client.NewSession()
	if err != nil {
		return
	}
	_ = session.Run("uptime")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Errorf("did not expect a SnkCommand flow for a constant command, got %d flows", len(flows))
	}
}

// --- SFTP remote path traversal (CWE-22) ---

func TestAnalyzeGo_SFTP_Open_PathTraversal(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/pkg/sftp"
)

func handler(w http.ResponseWriter, r *http.Request, sftpClient *sftp.Client) {
	path := r.URL.Query().Get("path")
	f, _ := sftpClient.Open(path)
	_ = f
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasSinkID(flows, "go.sftp.client.open") {
		t.Errorf("expected SnkFileRead flow attributed to go.sftp.client.open, got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_SFTP_Create_PathTraversal(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/pkg/sftp"
)

func handler(w http.ResponseWriter, r *http.Request, sftpClient *sftp.Client) {
	path := r.FormValue("dst")
	f, _ := sftpClient.Create(path)
	_ = f
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasSinkID(flows, "go.sftp.client.create") {
		t.Errorf("expected SnkFileWrite flow attributed to go.sftp.client.create, got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_SFTP_Rename_PathTraversal(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/pkg/sftp"
)

func handler(w http.ResponseWriter, r *http.Request, sftpClient *sftp.Client) {
	dst := r.URL.Query().Get("dst")
	_ = sftpClient.Rename("/tmp/incoming", dst)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasSinkID(flows, "go.sftp.client.rename") {
		t.Errorf("expected SnkFileWrite flow attributed to go.sftp.client.rename, got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_SFTP_ReadDir_PathTraversal(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/pkg/sftp"
)

func handler(w http.ResponseWriter, r *http.Request, sftpClient *sftp.Client) {
	dir := r.URL.Query().Get("dir")
	entries, _ := sftpClient.ReadDir(dir)
	_ = entries
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasSinkID(flows, "go.sftp.client.readdir") {
		t.Errorf("expected SnkFileRead flow attributed to go.sftp.client.readdir, got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_SFTP_RemoveAndMkdir_PathTraversal(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/pkg/sftp"
)

func handler(w http.ResponseWriter, r *http.Request, sftpClient *sftp.Client) {
	victim := r.URL.Query().Get("victim")
	_ = sftpClient.Remove(victim)
	dir := r.FormValue("dir")
	_ = sftpClient.MkdirAll(dir)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasSinkID(flows, "go.sftp.client.remove") {
		t.Errorf("expected flow attributed to go.sftp.client.remove, got %d flows", len(flows))
	}
	if !hasSinkID(flows, "go.sftp.client.mkdir") {
		t.Errorf("expected flow attributed to go.sftp.client.mkdir, got %d flows", len(flows))
	}
}

func TestAnalyzeGo_SFTP_Symlink_PathTraversal(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/pkg/sftp"
)

func handler(w http.ResponseWriter, r *http.Request, sftpClient *sftp.Client) {
	target := r.URL.Query().Get("target")
	_ = sftpClient.Symlink(target, "/srv/app/public/link")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasSinkID(flows, "go.sftp.client.symlink") {
		t.Errorf("expected flow attributed to go.sftp.client.symlink, got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// Negative: a constant remote path must not produce a flow.
func TestAnalyzeGo_SFTP_Open_ConstantPath_NoFlow(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/pkg/sftp"
)

func handler(w http.ResponseWriter, r *http.Request, sftpClient *sftp.Client) {
	f, _ := sftpClient.Open("/srv/app/config.yaml")
	_ = f
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if hasTaintFlow(flows, taint.SnkFileRead) || hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Errorf("did not expect a file-op flow for a constant path, got %d flows", len(flows))
	}
}
