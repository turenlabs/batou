package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Python SSH/SFTP — paramiko.SFTPClient + fabric.Connection sinks
// (CWE-78 command injection, CWE-22 path traversal, CWE-59 symlink)
// =========================================================================

func TestPython_FabricConnectionSudo(t *testing.T) {
	code := `
from fabric import Connection
from flask import request

def handler():
    cmd = request.args.get("cmd")
    c = Connection("user@host")
    c.sudo(cmd)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for request.args -> fabric Connection.sudo()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_FabricConnectionLocal(t *testing.T) {
	code := `
from fabric import Connection
from flask import request

def handler():
    cmd = request.args.get("cmd")
    conn = Connection("user@host")
    conn.local(cmd)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for request.args -> fabric Connection.local()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_ParamikoSFTPRemove(t *testing.T) {
	code := `
import paramiko
from flask import request

def handler():
    target = request.args.get("path")
    ssh = paramiko.SSHClient()
    ssh.connect("host")
    sftp = ssh.open_sftp()
    sftp.remove(target)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file-write flow for request.args -> paramiko SFTPClient.remove()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_ParamikoSFTPRename(t *testing.T) {
	code := `
import paramiko
from flask import request

def handler():
    new_name = request.args.get("newpath")
    ssh = paramiko.SSHClient()
    ssh.connect("host")
    sftp = ssh.open_sftp()
    sftp.rename("/tmp/orig.txt", new_name)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file-write flow for request.args -> paramiko SFTPClient.rename()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_ParamikoSFTPSymlink(t *testing.T) {
	code := `
import paramiko
from flask import request

def handler():
    dest = request.args.get("dest")
    ssh = paramiko.SSHClient()
    ssh.connect("host")
    sftp = ssh.open_sftp()
    sftp.symlink("/etc/passwd", dest)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file-write flow for request.args -> paramiko SFTPClient.symlink()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_ParamikoSFTPMkdir(t *testing.T) {
	code := `
import paramiko
from flask import request

def handler():
    dirname = request.args.get("dir")
    ssh = paramiko.SSHClient()
    ssh.connect("host")
    sftp = ssh.open_sftp()
    sftp.mkdir(dirname)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file-write flow for request.args -> paramiko SFTPClient.mkdir()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
