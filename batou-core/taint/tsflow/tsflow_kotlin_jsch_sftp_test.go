package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// JSch ChannelSftp remote file-op sinks for Kotlin (CWE-22 path traversal, CWE-918 SSRF).
//
// Kotlin's catalog previously had only `kotlin.jsch.setcommand` (ChannelExec) for SSH.
// The JSch SFTP subsystem (`com.jcraft.jsch.ChannelSftp`) — the dominant JVM SFTP client
// used by Spring Integration, Apache Camel, Gradle, Ant, Jenkins, and most Kotlin
// deployment tooling — exposed put/get/mkdir/rmdir/rm/rename/symlink/hardlink/chmod/
// chown/chgrp/ls/stat/realpath without modelling. Coupled with `JSch.getSession` SSRF
// (attacker-chosen SSH target host), this rounds out JVM SSH/SFTP parity with the Java
// JSch (#727), Ruby Net::SSH (#724), PHP phpseclib3 (#725), Rust ssh2 (#726), and Go
// x/crypto/ssh+pkg/sftp (#731) waves.
//
// Receiver-binding: ObjectType "com.jcraft.jsch.ChannelSftp" binds receivers
// `channelSftp` (lower==lastPart "channelsftp") and `channel`
// (HasPrefix("channelsftp", "channel")=true) via tsflow matcher heuristics. The
// shorter canonical receiver `sftp` does NOT bind via lastPart — those uses hit
// Layer 1 regex fallback only. All positive tests below use receiver `channelSftp`
// or `channel` to exercise the tsflow path.
//
// Taint source: `readLine()` (kotlin.readLine), wrapped in a plain `fun handler()`
// to avoid the cycle #759 web-handler auto-taint trigger (no executeQuery/Query(/
// Path(/Json(/Form( substrings in the fixtures).

// hasFlowFromSink reports whether any flow reached a sink with the given ID and category.
func hasFlowFromSink(flows []taint.TaintFlow, sinkID string, sinkCat taint.SinkCategory) bool {
	for _, f := range flows {
		if f.Sink.ID == sinkID && f.Sink.Category == sinkCat {
			return true
		}
	}
	return false
}

// --- put(src, dst) — local→remote upload, both path args dangerous ---

func TestKotlin_JSch_ChannelSftp_Put_PathTraversal(t *testing.T) {
	code := `
fun handler() {
    val remote = readLine()
    channelSftp.put("/tmp/local.bin", remote)
}
`
	flows := Analyze(code, "/app/Uploader.kt", rules.LangKotlin)
	if !hasFlowFromSink(flows, "kotlin.jsch.channelsftp.put", taint.SnkFileWrite) {
		t.Errorf("expected SnkFileWrite flow for ChannelSftp.put; flows=%+v", flows)
	}
}

// --- get(src, dst) — remote→local download, remote path tainted ---

func TestKotlin_JSch_ChannelSftp_Get_PathTraversal(t *testing.T) {
	code := `
fun handler() {
    val remote = readLine()
    channelSftp.get(remote, "/tmp/out.bin")
}
`
	flows := Analyze(code, "/app/Downloader.kt", rules.LangKotlin)
	if !hasFlowFromSink(flows, "kotlin.jsch.channelsftp.get", taint.SnkFileRead) {
		t.Errorf("expected SnkFileRead flow for ChannelSftp.get; flows=%+v", flows)
	}
}

// --- mkdir(path) ---

func TestKotlin_JSch_ChannelSftp_Mkdir_PathTraversal(t *testing.T) {
	code := `
fun handler() {
    val dir = readLine()
    channelSftp.mkdir(dir)
}
`
	flows := Analyze(code, "/app/DirMaker.kt", rules.LangKotlin)
	if !hasFlowFromSink(flows, "kotlin.jsch.channelsftp.mkdir", taint.SnkFileWrite) {
		t.Errorf("expected SnkFileWrite flow for ChannelSftp.mkdir; flows=%+v", flows)
	}
}

// --- rmdir(path) ---

func TestKotlin_JSch_ChannelSftp_Rmdir_PathTraversal(t *testing.T) {
	code := `
fun handler() {
    val dir = readLine()
    channelSftp.rmdir(dir)
}
`
	flows := Analyze(code, "/app/DirRemover.kt", rules.LangKotlin)
	if !hasFlowFromSink(flows, "kotlin.jsch.channelsftp.rmdir", taint.SnkFileWrite) {
		t.Errorf("expected SnkFileWrite flow for ChannelSftp.rmdir; flows=%+v", flows)
	}
}

// --- rm(path) ---

func TestKotlin_JSch_ChannelSftp_Rm_PathTraversal(t *testing.T) {
	code := `
fun handler() {
    val victim = readLine()
    channelSftp.rm(victim)
}
`
	flows := Analyze(code, "/app/FileRemover.kt", rules.LangKotlin)
	if !hasFlowFromSink(flows, "kotlin.jsch.channelsftp.rm", taint.SnkFileWrite) {
		t.Errorf("expected SnkFileWrite flow for ChannelSftp.rm; flows=%+v", flows)
	}
}

// --- rename(oldpath, newpath) — destination path tainted ---

func TestKotlin_JSch_ChannelSftp_Rename_PathTraversal(t *testing.T) {
	code := `
fun handler() {
    val dst = readLine()
    channelSftp.rename("/srv/old", dst)
}
`
	flows := Analyze(code, "/app/Renamer.kt", rules.LangKotlin)
	if !hasFlowFromSink(flows, "kotlin.jsch.channelsftp.rename", taint.SnkFileWrite) {
		t.Errorf("expected SnkFileWrite flow for ChannelSftp.rename; flows=%+v", flows)
	}
}

// --- symlink(target, linkpath) — uses `channel` receiver alias ---

func TestKotlin_JSch_ChannelSftp_Symlink_PathTraversal(t *testing.T) {
	code := `
fun handler() {
    val target = readLine()
    channel.symlink(target, "/srv/link")
}
`
	flows := Analyze(code, "/app/Linker.kt", rules.LangKotlin)
	if !hasFlowFromSink(flows, "kotlin.jsch.channelsftp.symlink", taint.SnkFileWrite) {
		t.Errorf("expected SnkFileWrite flow for ChannelSftp.symlink; flows=%+v", flows)
	}
}

// --- hardlink(target, linkpath) ---

func TestKotlin_JSch_ChannelSftp_Hardlink_PathTraversal(t *testing.T) {
	code := `
fun handler() {
    val target = readLine()
    channelSftp.hardlink(target, "/srv/hard")
}
`
	flows := Analyze(code, "/app/Linker.kt", rules.LangKotlin)
	if !hasFlowFromSink(flows, "kotlin.jsch.channelsftp.hardlink", taint.SnkFileWrite) {
		t.Errorf("expected SnkFileWrite flow for ChannelSftp.hardlink; flows=%+v", flows)
	}
}

// --- chmod(permissions, path) — path is arg index 1 ---

func TestKotlin_JSch_ChannelSftp_Chmod_PathTraversal(t *testing.T) {
	code := `
fun handler() {
    val path = readLine()
    channelSftp.chmod(493, path)
}
`
	flows := Analyze(code, "/app/Perms.kt", rules.LangKotlin)
	if !hasFlowFromSink(flows, "kotlin.jsch.channelsftp.chmod", taint.SnkFileWrite) {
		t.Errorf("expected SnkFileWrite flow for ChannelSftp.chmod; flows=%+v", flows)
	}
}

// --- chown(uid, path) — path is arg index 1 ---

func TestKotlin_JSch_ChannelSftp_Chown_PathTraversal(t *testing.T) {
	code := `
fun handler() {
    val path = readLine()
    channelSftp.chown(0, path)
}
`
	flows := Analyze(code, "/app/Owner.kt", rules.LangKotlin)
	if !hasFlowFromSink(flows, "kotlin.jsch.channelsftp.chown", taint.SnkFileWrite) {
		t.Errorf("expected SnkFileWrite flow for ChannelSftp.chown; flows=%+v", flows)
	}
}

// --- chgrp(gid, path) — path is arg index 1 ---

func TestKotlin_JSch_ChannelSftp_Chgrp_PathTraversal(t *testing.T) {
	code := `
fun handler() {
    val path = readLine()
    channelSftp.chgrp(0, path)
}
`
	flows := Analyze(code, "/app/Group.kt", rules.LangKotlin)
	if !hasFlowFromSink(flows, "kotlin.jsch.channelsftp.chgrp", taint.SnkFileWrite) {
		t.Errorf("expected SnkFileWrite flow for ChannelSftp.chgrp; flows=%+v", flows)
	}
}

// --- ls(path) ---

func TestKotlin_JSch_ChannelSftp_Ls_PathTraversal(t *testing.T) {
	code := `
fun handler() {
    val dir = readLine()
    channelSftp.ls(dir)
}
`
	flows := Analyze(code, "/app/Lister.kt", rules.LangKotlin)
	if !hasFlowFromSink(flows, "kotlin.jsch.channelsftp.ls", taint.SnkFileRead) {
		t.Errorf("expected SnkFileRead flow for ChannelSftp.ls; flows=%+v", flows)
	}
}

// --- stat(path) ---

func TestKotlin_JSch_ChannelSftp_Stat_PathTraversal(t *testing.T) {
	code := `
fun handler() {
    val path = readLine()
    channelSftp.stat(path)
}
`
	flows := Analyze(code, "/app/Stater.kt", rules.LangKotlin)
	if !hasFlowFromSink(flows, "kotlin.jsch.channelsftp.stat", taint.SnkFileRead) {
		t.Errorf("expected SnkFileRead flow for ChannelSftp.stat; flows=%+v", flows)
	}
}

// --- realpath(path) ---

func TestKotlin_JSch_ChannelSftp_Realpath_PathTraversal(t *testing.T) {
	code := `
fun handler() {
    val path = readLine()
    channelSftp.realpath(path)
}
`
	flows := Analyze(code, "/app/Resolver.kt", rules.LangKotlin)
	if !hasFlowFromSink(flows, "kotlin.jsch.channelsftp.realpath", taint.SnkFileRead) {
		t.Errorf("expected SnkFileRead flow for ChannelSftp.realpath; flows=%+v", flows)
	}
}

// --- JSch.getSession(user, host, port) — host is arg index 1 (SSRF) ---

func TestKotlin_JSch_GetSession_SSRF(t *testing.T) {
	code := `
fun handler() {
    val host = readLine()
    val session = jsch.getSession("svc", host, 22)
}
`
	flows := Analyze(code, "/app/Connector.kt", rules.LangKotlin)
	if !hasFlowFromSink(flows, "kotlin.jsch.jsch.getsession", taint.SnkURLFetch) {
		t.Errorf("expected SnkURLFetch (SSRF) flow for JSch.getSession; flows=%+v", flows)
	}
}

// --- Negative: constant remote path on ChannelSftp.put → no flow ---

func TestKotlin_JSch_ChannelSftp_Put_ConstantPath_Safe(t *testing.T) {
	code := `
fun handler() {
    channelSftp.put("/tmp/local.bin", "/srv/uploads/fixed.bin")
}
`
	flows := Analyze(code, "/app/Uploader.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.ID == "kotlin.jsch.channelsftp.put" {
			t.Errorf("did not expect a flow for constant-path ChannelSftp.put; got %+v", f)
		}
	}
}

// --- Negative: constant host on JSch.getSession → no flow ---

func TestKotlin_JSch_GetSession_ConstantHost_Safe(t *testing.T) {
	code := `
fun handler() {
    val session = jsch.getSession("svc", "ssh.internal.example.com", 22)
}
`
	flows := Analyze(code, "/app/Connector.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.ID == "kotlin.jsch.jsch.getsession" {
			t.Errorf("did not expect a flow for constant-host JSch.getSession; got %+v", f)
		}
	}
}

// --- Registration: all 15 new entries are present in the Kotlin sink catalog ---

func TestKotlin_JSch_SFTP_SinksRegistered(t *testing.T) {
	sinks := taint.SinksForLanguage(rules.LangKotlin)
	want := map[string]taint.SinkCategory{
		"kotlin.jsch.channelsftp.put":      taint.SnkFileWrite,
		"kotlin.jsch.channelsftp.get":      taint.SnkFileRead,
		"kotlin.jsch.channelsftp.mkdir":    taint.SnkFileWrite,
		"kotlin.jsch.channelsftp.rmdir":    taint.SnkFileWrite,
		"kotlin.jsch.channelsftp.rm":       taint.SnkFileWrite,
		"kotlin.jsch.channelsftp.rename":   taint.SnkFileWrite,
		"kotlin.jsch.channelsftp.symlink":  taint.SnkFileWrite,
		"kotlin.jsch.channelsftp.hardlink": taint.SnkFileWrite,
		"kotlin.jsch.channelsftp.chmod":    taint.SnkFileWrite,
		"kotlin.jsch.channelsftp.chown":    taint.SnkFileWrite,
		"kotlin.jsch.channelsftp.chgrp":    taint.SnkFileWrite,
		"kotlin.jsch.channelsftp.ls":       taint.SnkFileRead,
		"kotlin.jsch.channelsftp.stat":     taint.SnkFileRead,
		"kotlin.jsch.channelsftp.realpath": taint.SnkFileRead,
		"kotlin.jsch.jsch.getsession":      taint.SnkURLFetch,
	}
	got := make(map[string]taint.SinkCategory)
	for _, s := range sinks {
		if _, ok := want[s.ID]; ok {
			got[s.ID] = s.Category
		}
	}
	for id, cat := range want {
		gotCat, ok := got[id]
		if !ok {
			t.Errorf("sink %q not registered for Kotlin", id)
			continue
		}
		if gotCat != cat {
			t.Errorf("sink %q has category %q, want %q", id, gotCat, cat)
		}
	}
}
