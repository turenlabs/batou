package tsflow

import (
	"testing"

	_ "github.com/turenlabs/batou-core/taint/languages"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Ruby — Net::SSH / Net::SCP / Net::SFTP remote operations
//   ssh.exec!(cmd)        -> command injection on the remote host (CWE-78)
//   scp/sftp upload!/download!/remove!/rename!/mkdir!/open! with a tainted
//   remote or local path  -> path traversal (CWE-22)
// =========================================================================

// Net::SSH::Connection::Session#exec! with a tainted command string.
func TestRuby_NetSSH_ExecBang(t *testing.T) {
	code := `
def remote_exec(params)
  cmd = params[:command]
  Net::SSH.start(remote_host, ssh_user) do |ssh|
    ssh.exec!(cmd)
  end
end
`
	flows := Analyze(code, "/app/controllers/ops_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected Command flow for params -> Net::SSH#exec!")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Net::SCP#download! with a tainted remote path (arbitrary remote file read).
func TestRuby_NetSCP_DownloadBang(t *testing.T) {
	code := `
def fetch_remote(params)
  remote_path = params[:path]
  Net::SCP.start(remote_host, ssh_user) do |scp|
    scp.download!(remote_path, "/tmp/scratch")
  end
end
`
	flows := Analyze(code, "/app/controllers/transfer_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected FileRead flow for params -> Net::SCP#download!")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Net::SCP#upload! with a tainted remote destination path (arbitrary remote write).
func TestRuby_NetSCP_UploadBang(t *testing.T) {
	code := `
def push_remote(params)
  dest = params[:dest]
  Net::SCP.start(remote_host, ssh_user) do |scp|
    scp.upload!("/var/tmp/payload", dest)
  end
end
`
	flows := Analyze(code, "/app/controllers/transfer_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected FileWrite flow for params -> Net::SCP#upload!")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Net::SFTP::Session#download! with a tainted remote path.
func TestRuby_NetSFTP_DownloadBang(t *testing.T) {
	code := `
def sftp_fetch(params)
  remote_path = params[:remote]
  Net::SFTP.start(remote_host, ssh_user) do |sftp|
    sftp.download!(remote_path, "/tmp/out")
  end
end
`
	flows := Analyze(code, "/app/controllers/sftp_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected FileRead flow for params -> Net::SFTP#download!")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Net::SFTP::Session#upload! with a tainted remote destination path.
func TestRuby_NetSFTP_UploadBang(t *testing.T) {
	code := `
def sftp_put(params)
  remote_path = params[:remote]
  Net::SFTP.start(remote_host, ssh_user) do |sftp|
    sftp.upload!("/var/tmp/payload", remote_path)
  end
end
`
	flows := Analyze(code, "/app/controllers/sftp_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected FileWrite flow for params -> Net::SFTP#upload!")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Net::SFTP::Session#remove! with a tainted remote path (arbitrary remote delete).
func TestRuby_NetSFTP_RemoveBang(t *testing.T) {
	code := `
def sftp_delete(params)
  victim = params[:file]
  Net::SFTP.start(remote_host, ssh_user) do |sftp|
    sftp.remove!(victim)
  end
end
`
	flows := Analyze(code, "/app/controllers/sftp_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected FileWrite flow for params -> Net::SFTP#remove!")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Net::SFTP::Session#rename! with tainted remote paths.
func TestRuby_NetSFTP_RenameBang(t *testing.T) {
	code := `
def sftp_move(params)
  src = params[:src]
  Net::SFTP.start(remote_host, ssh_user) do |sftp|
    sftp.rename!(src, "/srv/data/archived")
  end
end
`
	flows := Analyze(code, "/app/controllers/sftp_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected FileWrite flow for params -> Net::SFTP#rename!")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Net::SFTP::Session#mkdir! with a tainted remote path.
func TestRuby_NetSFTP_MkdirBang(t *testing.T) {
	code := `
def sftp_makedir(params)
  dir = params[:dir]
  Net::SFTP.start(remote_host, ssh_user) do |sftp|
    sftp.mkdir!(dir)
  end
end
`
	flows := Analyze(code, "/app/controllers/sftp_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected FileWrite flow for params -> Net::SFTP#mkdir!")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Net::SFTP::Session#open! with a tainted remote path.
func TestRuby_NetSFTP_OpenBang(t *testing.T) {
	code := `
def sftp_open(params)
  target = params[:path]
  Net::SFTP.start(remote_host, ssh_user) do |sftp|
    sftp.open!(target, "w")
  end
end
`
	flows := Analyze(code, "/app/controllers/sftp_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected FileWrite flow for params -> Net::SFTP#open!")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Safe: Shellwords.escape neutralizes the command before Net::SSH#exec!.
func TestRuby_NetSSH_SafeShellwordsEscape(t *testing.T) {
	code := `
def remote_exec_safe(params)
  cmd = Shellwords.escape(params[:command])
  Net::SSH.start(remote_host, ssh_user) do |ssh|
    ssh.exec!(cmd)
  end
end
`
	flows := Analyze(code, "/app/controllers/ops_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("did not expect Command flow after Shellwords.escape sanitization")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Safe: constant remote/local paths — no taint reaches Net::SFTP#download!.
func TestRuby_NetSFTP_SafeConstantPaths(t *testing.T) {
	code := `
def sftp_fetch_motd
  Net::SFTP.start(remote_host, ssh_user) do |sftp|
    sftp.download!("/etc/motd", "/tmp/motd")
  end
end
`
	flows := Analyze(code, "/app/controllers/sftp_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("did not expect FileRead flow with constant paths")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
