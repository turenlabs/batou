package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Rust `ssh2` crate (libssh2 bindings) — SSH command exec + SFTP/SCP path
// traversal + direct-tcpip SSRF sinks.
//   Channel::exec                  -> SnkCommand   (CWE-78)
//   Sftp::open/opendir/readdir     -> SnkFileRead  (CWE-22)
//   Sftp::create/open_mode/mkdir/  -> SnkFileWrite (CWE-22)
//     unlink/rmdir/rename/symlink
//   Session::scp_recv              -> SnkFileRead  (CWE-22)
//   Session::scp_send              -> SnkFileWrite (CWE-22)
//   Session::channel_direct_tcpip  -> SnkURLFetch  (CWE-918)
// =========================================================================

func rustHasSinkID(flows []taint.TaintFlow, id string) bool {
	for _, f := range flows {
		if f.Sink.ID == id {
			return true
		}
	}
	return false
}

func TestRust_SSH2_SinksRegistered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangRust)
	if cat == nil {
		t.Fatal("Rust catalog not loaded")
	}
	found := map[string]bool{}
	for _, s := range cat.Sinks() {
		found[s.ID] = true
	}
	want := []string{
		"rust.ssh2.channel.exec",
		"rust.ssh2.sftp.open",
		"rust.ssh2.sftp.opendir",
		"rust.ssh2.sftp.readdir",
		"rust.ssh2.sftp.create",
		"rust.ssh2.sftp.open_mode",
		"rust.ssh2.sftp.mkdir",
		"rust.ssh2.sftp.unlink",
		"rust.ssh2.sftp.rmdir",
		"rust.ssh2.sftp.rename",
		"rust.ssh2.sftp.symlink",
		"rust.ssh2.session.scp_recv",
		"rust.ssh2.session.scp_send",
		"rust.ssh2.session.channel_direct_tcpip",
	}
	for _, id := range want {
		if !found[id] {
			t.Errorf("missing expected ssh2 sink: %s", id)
		}
	}
}

// ---------- Channel::exec — command injection (CWE-78) ----------

func TestRust_SSH2_ChannelExec_CommandInjection(t *testing.T) {
	code := `
use std::env;
use ssh2::Session;

fn run_remote(sess: &Session) {
    let cmd = env::var("USER_CMD").unwrap();
    let mut channel = sess.channel_session().unwrap();
    channel.exec(&cmd).unwrap();
}
`
	flows := Analyze(code, "/app/ssh.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow: env::var -> ssh2 Channel::exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
	if !rustHasSinkID(flows, "rust.ssh2.channel.exec") {
		t.Error("expected sink ID rust.ssh2.channel.exec")
	}
}

// ---------- Sftp::open — remote file read (CWE-22) ----------

func TestRust_SSH2_SftpOpen_FileRead(t *testing.T) {
	code := `
use std::env;
use std::path::Path;
use ssh2::Session;

fn fetch(sess: &Session) {
    let rel = env::var("REMOTE_PATH").unwrap();
    let sftp = sess.sftp().unwrap();
    let mut f = sftp.open(Path::new(&rel)).unwrap();
}
`
	flows := Analyze(code, "/app/ssh.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file-read flow: env::var -> ssh2 Sftp::open")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// ---------- Sftp::opendir / readdir — directory traversal (CWE-22) ----------

func TestRust_SSH2_SftpReaddir_FileRead(t *testing.T) {
	code := `
use std::env;
use std::path::Path;
use ssh2::Session;

fn list(sess: &Session) {
    let dir = env::var("REMOTE_DIR").unwrap();
    let sftp = sess.sftp().unwrap();
    let entries = sftp.readdir(Path::new(&dir)).unwrap();
}
`
	flows := Analyze(code, "/app/ssh.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file-read flow: env::var -> ssh2 Sftp::readdir")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestRust_SSH2_SftpOpendir_FileRead(t *testing.T) {
	code := `
use std::env;
use std::path::Path;
use ssh2::Session;

fn open_dir(sess: &Session) {
    let dir = env::var("REMOTE_DIR").unwrap();
    let sftp = sess.sftp().unwrap();
    let d = sftp.opendir(Path::new(&dir)).unwrap();
}
`
	flows := Analyze(code, "/app/ssh.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file-read flow: env::var -> ssh2 Sftp::opendir")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// ---------- Sftp::create / open_mode — remote file write (CWE-22) ----------

func TestRust_SSH2_SftpCreate_FileWrite(t *testing.T) {
	code := `
use std::env;
use std::path::Path;
use ssh2::Session;

fn upload(sess: &Session) {
    let dest = env::var("REMOTE_DEST").unwrap();
    let sftp = sess.sftp().unwrap();
    let mut f = sftp.create(Path::new(&dest)).unwrap();
}
`
	flows := Analyze(code, "/app/ssh.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file-write flow: env::var -> ssh2 Sftp::create")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestRust_SSH2_SftpOpenMode_FileWrite(t *testing.T) {
	code := `
use std::env;
use std::path::Path;
use ssh2::{Session, OpenFlags, OpenType};

fn write_file(sess: &Session) {
    let dest = env::var("REMOTE_DEST").unwrap();
    let sftp = sess.sftp().unwrap();
    let mut f = sftp.open_mode(Path::new(&dest), OpenFlags::WRITE | OpenFlags::CREATE, 0o644, OpenType::File).unwrap();
}
`
	flows := Analyze(code, "/app/ssh.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file-write flow: env::var -> ssh2 Sftp::open_mode")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// ---------- Sftp::mkdir / rmdir / unlink — traversal-driven write/delete ----------

func TestRust_SSH2_SftpMkdir_FileWrite(t *testing.T) {
	code := `
use std::env;
use std::path::Path;
use ssh2::Session;

fn make_dir(sess: &Session) {
    let dir = env::var("REMOTE_DIR").unwrap();
    let sftp = sess.sftp().unwrap();
    sftp.mkdir(Path::new(&dir), 0o755).unwrap();
}
`
	flows := Analyze(code, "/app/ssh.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file-write flow: env::var -> ssh2 Sftp::mkdir")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestRust_SSH2_SftpUnlink_FileWrite(t *testing.T) {
	code := `
use std::env;
use std::path::Path;
use ssh2::Session;

fn delete_remote(sess: &Session) {
    let target = env::var("REMOTE_TARGET").unwrap();
    let sftp = sess.sftp().unwrap();
    sftp.unlink(Path::new(&target)).unwrap();
}
`
	flows := Analyze(code, "/app/ssh.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file-write flow: env::var -> ssh2 Sftp::unlink")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestRust_SSH2_SftpRmdir_FileWrite(t *testing.T) {
	code := `
use std::env;
use std::path::Path;
use ssh2::Session;

fn remove_dir(sess: &Session) {
    let dir = env::var("REMOTE_DIR").unwrap();
    let sftp = sess.sftp().unwrap();
    sftp.rmdir(Path::new(&dir)).unwrap();
}
`
	flows := Analyze(code, "/app/ssh.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file-write flow: env::var -> ssh2 Sftp::rmdir")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// ---------- Sftp::rename — second-arg path also dangerous (CWE-22) ----------

func TestRust_SSH2_SftpRename_DstArg_FileWrite(t *testing.T) {
	code := `
use std::env;
use std::path::Path;
use ssh2::Session;

fn move_remote(sess: &Session) {
    let dst = env::var("REMOTE_DST").unwrap();
    let sftp = sess.sftp().unwrap();
    sftp.rename(Path::new("/tmp/staged"), Path::new(&dst), None).unwrap();
}
`
	flows := Analyze(code, "/app/ssh.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file-write flow: env::var (dst arg) -> ssh2 Sftp::rename")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// ---------- Sftp::symlink — link-following / traversal (CWE-22) ----------

func TestRust_SSH2_SftpSymlink_FileWrite(t *testing.T) {
	code := `
use std::env;
use std::path::Path;
use ssh2::Session;

fn link_remote(sess: &Session) {
    let link = env::var("REMOTE_LINK").unwrap();
    let sftp = sess.sftp().unwrap();
    sftp.symlink(Path::new(&link), Path::new("/etc/passwd")).unwrap();
}
`
	flows := Analyze(code, "/app/ssh.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file-write flow: env::var -> ssh2 Sftp::symlink")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// ---------- Session::scp_recv / scp_send — SCP transfers (CWE-22) ----------

func TestRust_SSH2_ScpRecv_FileRead(t *testing.T) {
	code := `
use std::env;
use std::path::Path;
use ssh2::Session;

fn download(sess: &Session) {
    let remote = env::var("REMOTE_PATH").unwrap();
    let (mut chan, _stat) = sess.scp_recv(Path::new(&remote)).unwrap();
}
`
	flows := Analyze(code, "/app/ssh.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file-read flow: env::var -> ssh2 Session::scp_recv")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestRust_SSH2_ScpSend_FileWrite(t *testing.T) {
	code := `
use std::env;
use std::path::Path;
use ssh2::Session;

fn upload(sess: &Session, size: u64) {
    let remote = env::var("REMOTE_PATH").unwrap();
    let mut chan = sess.scp_send(Path::new(&remote), 0o644, size, None).unwrap();
}
`
	flows := Analyze(code, "/app/ssh.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file-write flow: env::var -> ssh2 Session::scp_send")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// ---------- Session::channel_direct_tcpip — SSRF from the SSH host (CWE-918) ----------

func TestRust_SSH2_DirectTcpip_SSRF(t *testing.T) {
	code := `
use std::env;
use ssh2::Session;

fn tunnel(sess: &Session) {
    let host = env::var("TARGET_HOST").unwrap();
    let mut chan = sess.channel_direct_tcpip(&host, 80, None).unwrap();
}
`
	flows := Analyze(code, "/app/ssh.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow: env::var -> ssh2 Session::channel_direct_tcpip")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// ---------- Negative: hardcoded paths/commands must not flow ----------

func TestRust_SSH2_HardcodedPaths_NoFlow(t *testing.T) {
	code := `
use std::path::Path;
use ssh2::Session;

fn safe(sess: &Session) {
    let mut channel = sess.channel_session().unwrap();
    channel.exec("uptime").unwrap();
    let sftp = sess.sftp().unwrap();
    let _ = sftp.open(Path::new("/etc/hostname")).unwrap();
    let _ = sftp.create(Path::new("/var/log/app.log")).unwrap();
    sftp.mkdir(Path::new("/srv/data"), 0o755).unwrap();
    let _ = sess.scp_recv(Path::new("/opt/build/artifact.tar")).unwrap();
}
`
	flows := Analyze(code, "/app/ssh.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.ID == "rust.ssh2.channel.exec" ||
			f.Sink.ID == "rust.ssh2.sftp.open" ||
			f.Sink.ID == "rust.ssh2.sftp.create" ||
			f.Sink.ID == "rust.ssh2.sftp.mkdir" ||
			f.Sink.ID == "rust.ssh2.session.scp_recv" {
			t.Errorf("unexpected flow to %s for hardcoded input (conf: %.2f)", f.Sink.ID, f.Confidence)
		}
	}
}
