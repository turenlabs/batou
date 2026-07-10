package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Swift — SSH / SFTP remote-operation sinks (Citadel, Shout, NMSSH)
// =========================================================================
//
// Until this cycle, Swift was the only tsflow language with no SSH/SFTP
// coverage (the cross-language SSH wave touched c, cpp, java, kotlin, ruby,
// php, rust, perl, groovy, go — but skipped swift). These tests exercise the
// 13 new sinks added to swift_sinks.go:
//
//   CWE-78  command exec : swift.citadel.executecommand, swift.shout.ssh.execute
//   CWE-918 SSRF (host)  : swift.citadel.sshclient.connect, swift.shout.ssh.connect,
//                          swift.nmssh.session.connect
//   CWE-22  SFTP traversal: swift.sftp.openfile, swift.sftp.listdirectory,
//                          swift.sftp.createdirectory, swift.sftp.removepath,
//                          swift.sftp.rename, swift.sftp.listfiles,
//                          swift.sftp.upload, swift.sftp.download
//
// Source side: Vapor `req.query["..."]` (swift.vapor.req.query, SrcUserInput),
// the same source the existing tsflow_swift_vapor_client_test.go SSRF tests
// use. The tsflow walker only walks code inside `function_declaration` bodies,
// so every fixture wraps the call site in a `func handler(...)`.

// ---------- registration ----------

func TestSwift_SSH_SFTP_SinksRegistered(t *testing.T) {
	want := []string{
		"swift.citadel.executecommand",
		"swift.shout.ssh.execute",
		"swift.citadel.sshclient.connect",
		"swift.shout.ssh.connect",
		"swift.nmssh.session.connect",
		"swift.sftp.openfile",
		"swift.sftp.listdirectory",
		"swift.sftp.createdirectory",
		"swift.sftp.removepath",
		"swift.sftp.rename",
		"swift.sftp.listfiles",
		"swift.sftp.upload",
		"swift.sftp.download",
	}
	got := map[string]bool{}
	for _, s := range taint.SinksForLanguage(rules.LangSwift) {
		got[s.ID] = true
	}
	for _, id := range want {
		if !got[id] {
			t.Errorf("sink %q not registered for Swift", id)
		}
	}
}

// ---------- CWE-78: remote command execution ----------

// Citadel: client.executeCommand("...\(input)") — remote command injection.
func TestSwift_Citadel_ExecuteCommand_Tainted(t *testing.T) {
	code := `
import Citadel

func handler(req: Request) async throws {
    let dir = req.query["dir"]
    let stdout = try await client.executeCommand("ls -la \(dir)")
    _ = stdout
}
`
	flows := Analyze(code, "/app/Exec.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Errorf("expected SnkCommand flow for req.query -> client.executeCommand; got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf %.2f) id=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// Citadel: client.executeCommandStream("...\(input)") — streaming variant.
func TestSwift_Citadel_ExecuteCommandStream_Tainted(t *testing.T) {
	code := `
import Citadel

func handler(req: Request) async throws {
    let cmd = req.query["cmd"]
    let stream = try await client.executeCommandStream("sh -c \(cmd)")
    _ = stream
}
`
	flows := Analyze(code, "/app/ExecStream.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Errorf("expected SnkCommand flow for req.query -> client.executeCommandStream; got %d flows", len(flows))
	}
}

// Shout: ssh.execute("...\(input)") — remote command injection.
func TestSwift_Shout_SSHExecute_Tainted(t *testing.T) {
	code := `
import Shout

func handler(req: Request) throws {
    let pkg = req.query["pkg"]
    try ssh.execute("apt-get install -y \(pkg)")
}
`
	flows := Analyze(code, "/app/Install.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Errorf("expected SnkCommand flow for req.query -> ssh.execute; got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf %.2f) id=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// Shout: ssh.capture("...\(input)") — capture variant of the same sink entry.
func TestSwift_Shout_SSHCapture_Tainted(t *testing.T) {
	code := `
import Shout

func handler(req: Request) throws {
    let path = req.query["path"]
    let (status, out) = try ssh.capture("cat \(path)")
    _ = status
    _ = out
}
`
	flows := Analyze(code, "/app/Cat.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Errorf("expected SnkCommand flow for req.query -> ssh.capture; got %d flows", len(flows))
	}
}

// ---------- CWE-918: SSH connect to a user-controlled host ----------

// Citadel: SSHClient.connect(host: tainted, ...) — SSRF-style host steering.
func TestSwift_Citadel_SSHClientConnect_TaintedHost(t *testing.T) {
	code := `
import Citadel

func handler(req: Request) async throws {
    let target = req.query["host"]
    let client = try await SSHClient.connect(host: target, authenticationMethod: .passwordBased(username: "u", password: "p"), hostKeyValidator: .acceptAnything(), reconnect: .never)
    _ = client
}
`
	flows := Analyze(code, "/app/Connect.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Errorf("expected SnkURLFetch flow for req.query -> SSHClient.connect(host:); got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf %.2f) id=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// Shout: SSH(host: tainted) — constructor form.
func TestSwift_Shout_SSHInit_TaintedHost(t *testing.T) {
	code := `
import Shout

func handler(req: Request) throws {
    let target = req.query["host"]
    let ssh = try SSH(host: target)
    _ = ssh
}
`
	flows := Analyze(code, "/app/ShoutConnect.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Errorf("expected SnkURLFetch flow for req.query -> SSH(host:); got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf %.2f) id=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// Shout: SSH.connect(host: tainted) { ... } — static form.
func TestSwift_Shout_SSHConnectStatic_TaintedHost(t *testing.T) {
	code := `
import Shout

func handler(req: Request) throws {
    let target = req.query["host"]
    try SSH.connect(host: target) { ssh in
        try ssh.authenticate(username: "u", privateKey: "k")
    }
}
`
	flows := Analyze(code, "/app/ShoutConnectStatic.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Errorf("expected SnkURLFetch flow for req.query -> SSH.connect(host:); got %d flows", len(flows))
	}
}

// NMSSH: NMSSHSession.connect(toHost: tainted, withUsername: ...) — static form.
func TestSwift_NMSSH_SessionConnect_TaintedHost(t *testing.T) {
	code := `
import NMSSH

func handler(req: Request) {
    let target = req.query["host"]
    let session = NMSSHSession.connect(toHost: target, withUsername: "u")
    _ = session
}
`
	flows := Analyze(code, "/app/NMSSHConnect.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Errorf("expected SnkURLFetch flow for req.query -> NMSSHSession.connect(toHost:); got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf %.2f) id=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// NMSSH: NMSSHSession(host: tainted, andUsername: ...) — constructor form.
func TestSwift_NMSSH_SessionInit_TaintedHost(t *testing.T) {
	code := `
import NMSSH

func handler(req: Request) {
    let target = req.query["host"]
    let session = NMSSHSession(host: target, andUsername: "u")
    _ = session
}
`
	flows := Analyze(code, "/app/NMSSHInit.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Errorf("expected SnkURLFetch flow for req.query -> NMSSHSession(host:); got %d flows", len(flows))
	}
}

// ---------- CWE-22: SFTP file operations with a user-controlled path ----------

// Citadel: sftp.openFile(filePath: "...\(name)", flags:) — remote path traversal.
func TestSwift_SFTP_OpenFile_TaintedPath(t *testing.T) {
	code := `
import Citadel

func handler(req: Request) async throws {
    let name = req.query["name"]
    let sftp = try await client.openSFTP()
    let file = try await sftp.openFile(filePath: "/srv/data/\(name)", flags: .read)
    _ = file
}
`
	flows := Analyze(code, "/app/Open.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Errorf("expected SnkFileWrite flow for req.query -> sftp.openFile(filePath:); got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf %.2f) id=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// Citadel: sftp.withFile(filePath: "...\(name)", flags:) { ... } — closure form.
func TestSwift_SFTP_WithFile_TaintedPath(t *testing.T) {
	code := `
import Citadel

func handler(req: Request) async throws {
    let name = req.query["name"]
    let sftp = try await client.openSFTP()
    try await sftp.withFile(filePath: "/srv/data/\(name)", flags: [.read]) { file in
        _ = try await file.readAll()
    }
}
`
	flows := Analyze(code, "/app/WithFile.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Errorf("expected SnkFileWrite flow for req.query -> sftp.withFile(filePath:); got %d flows", len(flows))
	}
}

// Citadel: sftp.listDirectory(atPath: "...\(dir)") — remote dir enumeration.
func TestSwift_SFTP_ListDirectory_TaintedPath(t *testing.T) {
	code := `
import Citadel

func handler(req: Request) async throws {
    let dir = req.query["dir"]
    let sftp = try await client.openSFTP()
    let entries = try await sftp.listDirectory(atPath: "/srv/data/\(dir)")
    _ = entries
}
`
	flows := Analyze(code, "/app/List.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Errorf("expected SnkFileRead flow for req.query -> sftp.listDirectory(atPath:); got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf %.2f) id=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// Citadel/Shout: sftp.createDirectory(atPath: "...\(dir)").
func TestSwift_SFTP_CreateDirectory_TaintedPath(t *testing.T) {
	code := `
import Citadel

func handler(req: Request) async throws {
    let dir = req.query["dir"]
    let sftp = try await client.openSFTP()
    try await sftp.createDirectory(atPath: "/srv/data/\(dir)")
}
`
	flows := Analyze(code, "/app/Mkdir.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Errorf("expected SnkFileWrite flow for req.query -> sftp.createDirectory(atPath:); got %d flows", len(flows))
	}
}

// Citadel: sftp.rmdir(at: "...\(dir)") — remote deletion.
func TestSwift_SFTP_Rmdir_TaintedPath(t *testing.T) {
	code := `
import Citadel

func handler(req: Request) async throws {
    let dir = req.query["dir"]
    let sftp = try await client.openSFTP()
    try await sftp.rmdir(at: "/srv/data/\(dir)")
}
`
	flows := Analyze(code, "/app/Rmdir.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Errorf("expected SnkFileWrite flow for req.query -> sftp.rmdir(at:); got %d flows", len(flows))
	}
}

// Shout: sftp.removeFile("...\(name)") — covered by swift.sftp.removepath.
func TestSwift_SFTP_RemoveFile_TaintedPath(t *testing.T) {
	code := `
import Shout

func handler(req: Request) throws {
    let name = req.query["name"]
    let sftp = try ssh.openSftp()
    try sftp.removeFile("/srv/data/\(name)")
}
`
	flows := Analyze(code, "/app/RemoveFile.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Errorf("expected SnkFileWrite flow for req.query -> sftp.removeFile; got %d flows", len(flows))
	}
}

// Citadel/Shout: sftp.rename(at: "...\(src)", to: ...) — arg 0 tainted.
func TestSwift_SFTP_Rename_TaintedSrc(t *testing.T) {
	code := `
import Citadel

func handler(req: Request) async throws {
    let src = req.query["src"]
    let sftp = try await client.openSFTP()
    try await sftp.rename(at: "/srv/data/\(src)", to: "/srv/data/archived")
}
`
	flows := Analyze(code, "/app/RenameSrc.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Errorf("expected SnkFileWrite flow for req.query -> sftp.rename(at:); got %d flows", len(flows))
	}
}

// Citadel/Shout: sftp.rename(at: ..., to: "...\(dest)") — arg 1 tainted.
func TestSwift_SFTP_Rename_TaintedDest(t *testing.T) {
	code := `
import Citadel

func handler(req: Request) async throws {
    let dest = req.query["dest"]
    let sftp = try await client.openSFTP()
    try await sftp.rename(at: "/srv/data/incoming", to: "/srv/data/\(dest)")
}
`
	flows := Analyze(code, "/app/RenameDest.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Errorf("expected SnkFileWrite flow for req.query -> sftp.rename(to:); got %d flows", len(flows))
	}
}

// Shout: sftp.listFiles(in: "...\(dir)") — remote dir enumeration.
func TestSwift_SFTP_ListFiles_TaintedPath(t *testing.T) {
	code := `
import Shout

func handler(req: Request) throws {
    let dir = req.query["dir"]
    let sftp = try ssh.openSftp()
    let files = try sftp.listFiles(in: "/srv/data/\(dir)")
    _ = files
}
`
	flows := Analyze(code, "/app/ListFiles.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Errorf("expected SnkFileRead flow for req.query -> sftp.listFiles(in:); got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf %.2f) id=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// Shout: sftp.upload(localURL: ..., remotePath: "...\(name)") — arg 1 tainted.
func TestSwift_SFTP_Upload_TaintedRemotePath(t *testing.T) {
	code := `
import Shout
import Foundation

func handler(req: Request) throws {
    let name = req.query["name"]
    let sftp = try ssh.openSftp()
    try sftp.upload(localURL: URL(fileURLWithPath: "/tmp/payload"), remotePath: "/var/www/html/\(name)")
}
`
	flows := Analyze(code, "/app/Upload.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Errorf("expected SnkFileWrite flow for req.query -> sftp.upload(remotePath:); got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf %.2f) id=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// Shout: sftp.download(remotePath: "...\(name)", localURL: ...) — arg 0 tainted.
func TestSwift_SFTP_Download_TaintedRemotePath(t *testing.T) {
	code := `
import Shout
import Foundation

func handler(req: Request) throws {
    let name = req.query["name"]
    let sftp = try ssh.openSftp()
    try sftp.download(remotePath: "/srv/data/\(name)", localURL: URL(fileURLWithPath: "/tmp/out"))
}
`
	flows := Analyze(code, "/app/Download.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Errorf("expected SnkFileWrite flow for req.query -> sftp.download(remotePath:); got %d flows", len(flows))
	}
}

// ---------- negative controls ----------

// Constant command — no tainted data — must not flow.
func TestSwift_Citadel_ExecuteCommand_Constant_NoFlow(t *testing.T) {
	code := `
import Citadel

func handler(req: Request) async throws {
    _ = req.query["ignored"]
    let stdout = try await client.executeCommand("uptime")
    _ = stdout
}
`
	flows := Analyze(code, "/app/ExecConst.swift", rules.LangSwift)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Errorf("did not expect SnkCommand flow for constant executeCommand; got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf %.2f) id=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// Constant SFTP path — no tainted data — must not flow.
func TestSwift_SFTP_OpenFile_Constant_NoFlow(t *testing.T) {
	code := `
import Citadel

func handler(req: Request) async throws {
    _ = req.query["ignored"]
    let sftp = try await client.openSFTP()
    let file = try await sftp.openFile(filePath: "/srv/data/config.json", flags: .read)
    _ = file
}
`
	flows := Analyze(code, "/app/OpenConst.swift", rules.LangSwift)
	if hasTaintFlow(flows, taint.SnkFileWrite) || hasTaintFlow(flows, taint.SnkFileRead) {
		t.Errorf("did not expect SFTP flow for constant openFile path; got %d flows", len(flows))
	}
}

// Constant SSH host — no tainted data — must not flow.
func TestSwift_Shout_SSHInit_Constant_NoFlow(t *testing.T) {
	code := `
import Shout

func handler(req: Request) throws {
    _ = req.query["ignored"]
    let ssh = try SSH(host: "build.internal.example.com")
    _ = ssh
}
`
	flows := Analyze(code, "/app/SSHConst.swift", rules.LangSwift)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Errorf("did not expect SnkURLFetch flow for constant SSH host; got %d flows", len(flows))
	}
}
