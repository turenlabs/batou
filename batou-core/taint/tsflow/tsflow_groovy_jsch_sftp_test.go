package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// JSch SSH/SFTP sinks for Groovy — com.jcraft.jsch remote operations.
//
// Groovy's catalog previously had only the Jenkins `ssh-steps` plugin DSL
// (groovy.jenkins.sshcommand / groovy.jenkins.sshscript) for SSH; raw JSch is
// the dominant JVM SSH/SFTP client and is used directly in Gradle build
// scripts, Jenkins shared libraries, and Groovy deployment/automation tooling.
// This rounds out JVM SSH/SFTP parity with the Java JSch (#727), Kotlin JSch
// (#732), Ruby Net::SSH (#724), PHP phpseclib3 (#725), Rust ssh2 (#726), and
// Go x/crypto/ssh+pkg/sftp (#731) waves.
//
// Receiver-binding (tsflow matcher.go heuristics): ObjectType last component
// "channelsftp" binds receivers `channelSftp` (lower==lastPart) and `channel`
// (HasPrefix("channelsftp","channel")=true). The shorter canonical receiver
// `sftp` does NOT bind via lastPart (HasPrefix("channelsftp","sftp") is false)
// — those uses hit the Layer 1 regex fallback only. All positive tests below
// use receivers `channelSftp` / `channel` / `channelExec` / `jsch` to exercise
// the tsflow path.
//
// Source: `request.getParameter("...")` (groovy.grails.request.getparameter,
// ObjectType "HttpServletRequest"). Function names are deliberately neutral
// (no Query(/Path(/Json(/Form( substrings and no bare GET/POST tokens) so the
// tsflow walker's isWebHandlerFunc auto-taint heuristic is not the thing under
// test — the flows below come from the explicit source call.

// --- ChannelExec.setCommand(command) — RCE on remote host (CWE-78) ---

func TestGroovy_JSch_ChannelExec_SetCommand_CommandInjection(t *testing.T) {
	code := `
def runRemote(request) {
    def cmd = request.getParameter("cmd")
    channelExec.setCommand("/usr/bin/deploy " + cmd)
    channelExec.connect()
}
`
	flows := Analyze(code, "/app/RemoteRunner.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for ChannelExec.setCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

// --- ChannelSftp.put(src, dst) — local→remote upload, both args path-controlled (CWE-22) ---

func TestGroovy_JSch_ChannelSftp_Put_PathTraversal(t *testing.T) {
	code := `
def uploadArtifact(request) {
    def remote = request.getParameter("dest")
    channelSftp.put("/tmp/build.tar.gz", remote)
}
`
	flows := Analyze(code, "/app/Uploader.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected SnkFileWrite flow for ChannelSftp.put")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

// --- ChannelSftp.get(src, dst) — remote→local download, remote path tainted (CWE-22) ---

func TestGroovy_JSch_ChannelSftp_Get_PathTraversal(t *testing.T) {
	code := `
def fetchArtifact(request) {
    def remote = request.getParameter("src")
    channelSftp.get(remote, "/tmp/out.bin")
}
`
	flows := Analyze(code, "/app/Downloader.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected SnkFileRead flow for ChannelSftp.get")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

// --- ChannelSftp.mkdir(path) (CWE-22) ---

func TestGroovy_JSch_ChannelSftp_Mkdir_PathTraversal(t *testing.T) {
	code := `
def makeReleaseDir(request) {
    def dir = request.getParameter("dir")
    channelSftp.mkdir(dir)
}
`
	flows := Analyze(code, "/app/DirMaker.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected SnkFileWrite flow for ChannelSftp.mkdir")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

// --- ChannelSftp.rmdir(path) (CWE-22) ---

func TestGroovy_JSch_ChannelSftp_Rmdir_PathTraversal(t *testing.T) {
	code := `
def removeReleaseDir(request) {
    def dir = request.getParameter("dir")
    channelSftp.rmdir(dir)
}
`
	flows := Analyze(code, "/app/DirRemover.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected SnkFileWrite flow for ChannelSftp.rmdir")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

// --- ChannelSftp.rm(path) (CWE-22) ---

func TestGroovy_JSch_ChannelSftp_Rm_PathTraversal(t *testing.T) {
	code := `
def deleteRemoteFile(request) {
    def victim = request.getParameter("target")
    channelSftp.rm(victim)
}
`
	flows := Analyze(code, "/app/FileRemover.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected SnkFileWrite flow for ChannelSftp.rm")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

// --- ChannelSftp.rename(oldpath, newpath) — tainted destination (CWE-22) ---

func TestGroovy_JSch_ChannelSftp_Rename_PathTraversal(t *testing.T) {
	code := `
def relocate(request) {
    def dst = request.getParameter("dst")
    channelSftp.rename("/srv/old", dst)
}
`
	flows := Analyze(code, "/app/Renamer.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected SnkFileWrite flow for ChannelSftp.rename")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

// --- ChannelSftp.symlink(target, linkpath) (CWE-22) ---

func TestGroovy_JSch_ChannelSftp_Symlink_PathTraversal(t *testing.T) {
	code := `
def linkLatest(request) {
    def link = request.getParameter("link")
    channelSftp.symlink("/srv/releases/v1", link)
}
`
	flows := Analyze(code, "/app/Linker.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected SnkFileWrite flow for ChannelSftp.symlink")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

// --- ChannelSftp.hardlink(target, linkpath) — Mwiede fork extension (CWE-22) ---

func TestGroovy_JSch_ChannelSftp_Hardlink_PathTraversal(t *testing.T) {
	code := `
def hardLinkLatest(request) {
    def link = request.getParameter("link")
    channelSftp.hardlink("/srv/releases/v1", link)
}
`
	flows := Analyze(code, "/app/HardLinker.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected SnkFileWrite flow for ChannelSftp.hardlink")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

// --- ChannelSftp.chmod(permissions, path) — tainted path at arg 1 (CWE-22) ---

func TestGroovy_JSch_ChannelSftp_Chmod_PathTraversal(t *testing.T) {
	code := `
def relax(request) {
    def path = request.getParameter("path")
    channelSftp.chmod(0644, path)
}
`
	flows := Analyze(code, "/app/Chmodder.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected SnkFileWrite flow for ChannelSftp.chmod")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

// --- ChannelSftp.chown(uid, path) — tainted path at arg 1 (CWE-22) ---

func TestGroovy_JSch_ChannelSftp_Chown_PathTraversal(t *testing.T) {
	code := `
def reown(request) {
    def path = request.getParameter("path")
    channelSftp.chown(1000, path)
}
`
	flows := Analyze(code, "/app/Chowner.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected SnkFileWrite flow for ChannelSftp.chown")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

// --- ChannelSftp.chgrp(gid, path) — tainted path at arg 1 (CWE-22) ---

func TestGroovy_JSch_ChannelSftp_Chgrp_PathTraversal(t *testing.T) {
	code := `
def regroup(request) {
    def path = request.getParameter("path")
    channelSftp.chgrp(1000, path)
}
`
	flows := Analyze(code, "/app/Chgrpper.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected SnkFileWrite flow for ChannelSftp.chgrp")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

// --- ChannelSftp.ls(path) — remote directory enumeration (CWE-22) ---

func TestGroovy_JSch_ChannelSftp_Ls_PathTraversal(t *testing.T) {
	code := `
def listRemote(request) {
    def dir = request.getParameter("dir")
    def entries = channelSftp.ls(dir)
    return entries
}
`
	flows := Analyze(code, "/app/Lister.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected SnkFileRead flow for ChannelSftp.ls")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

// --- ChannelSftp.stat(path) — remote file metadata disclosure (CWE-22) ---

func TestGroovy_JSch_ChannelSftp_Stat_PathTraversal(t *testing.T) {
	code := `
def statRemote(request) {
    def path = request.getParameter("path")
    def attrs = channelSftp.stat(path)
    return attrs
}
`
	flows := Analyze(code, "/app/Statter.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected SnkFileRead flow for ChannelSftp.stat")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

// --- ChannelSftp.realpath(path) — symlink resolution on attacker-chosen file (CWE-22) ---

func TestGroovy_JSch_ChannelSftp_Realpath_PathTraversal(t *testing.T) {
	code := `
def resolveRemote(request) {
    def path = request.getParameter("path")
    def real = channelSftp.realpath(path)
    return real
}
`
	flows := Analyze(code, "/app/Resolver.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected SnkFileRead flow for ChannelSftp.realpath")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

// --- JSch.getSession(user, host, port) — SSH SSRF, tainted host at arg 1 (CWE-918) ---

func TestGroovy_JSch_GetSession_SSRF(t *testing.T) {
	code := `
def connectTarget(request) {
    def host = request.getParameter("host")
    def session = jsch.getSession("deploy", host, 22)
    session.connect()
}
`
	flows := Analyze(code, "/app/Connector.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SnkURLFetch (SSRF) flow for JSch.getSession")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

// --- Negative: constant paths must NOT produce a user-input path-traversal flow ---
// Proves the new ChannelSftp sinks don't over-match when the path arguments are
// literals (the common "deploy a fixed artifact to a fixed location" case).

func TestGroovy_JSch_ChannelSftp_NoFlowOnConstantPaths(t *testing.T) {
	code := `
def deployStatic() {
    channelSftp.put("/tmp/build.tar.gz", "/srv/releases/latest.tar.gz")
    channelSftp.mkdir("/srv/releases/v1")
    channelExec.setCommand("/usr/bin/restart-service")
}
`
	flows := Analyze(code, "/app/StaticDeploy.groovy", rules.LangGroovy)
	for _, f := range flows {
		if f.Source.Category == taint.SrcUserInput &&
			(f.Sink.Category == taint.SnkFileWrite || f.Sink.Category == taint.SnkFileRead || f.Sink.Category == taint.SnkCommand) {
			t.Errorf("unexpected user-input flow on constant paths: source=%s sink=%s", f.Source.ID, f.Sink.ID)
		}
	}
}

// --- Catalog wiring assertion — fast feedback if an entry is dropped/renamed ---

func TestGroovy_JSch_SinksRegistered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangGroovy)
	if cat == nil {
		t.Fatal("Groovy catalog not loaded")
	}
	have := map[string]bool{}
	for _, s := range cat.Sinks() {
		have[s.ID] = true
	}
	expected := []string{
		"groovy.jsch.channelexec.setcommand",
		"groovy.jsch.channelsftp.put",
		"groovy.jsch.channelsftp.get",
		"groovy.jsch.channelsftp.mkdir",
		"groovy.jsch.channelsftp.rmdir",
		"groovy.jsch.channelsftp.rm",
		"groovy.jsch.channelsftp.rename",
		"groovy.jsch.channelsftp.symlink",
		"groovy.jsch.channelsftp.hardlink",
		"groovy.jsch.channelsftp.chmod",
		"groovy.jsch.channelsftp.chown",
		"groovy.jsch.channelsftp.chgrp",
		"groovy.jsch.channelsftp.ls",
		"groovy.jsch.channelsftp.stat",
		"groovy.jsch.channelsftp.realpath",
		"groovy.jsch.jsch.getsession",
	}
	for _, id := range expected {
		if !have[id] {
			t.Errorf("expected sink %q to be registered", id)
		}
	}
}
