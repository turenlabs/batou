package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Perl — SSH/SFTP/SCP remote file-operation + remote-command sinks
//
// Covers the Perl SSH/SFTP modules that were not yet in the catalog:
//   - Net::SFTP::Foreign  ($sftp->get/put/get_content/put_content/mget/mput/
//                           rget/rput/ls/remove/rremove/setstat)            CWE-22
//   - Net::OpenSSH        ($ssh->rsync_get — counterpart of rsync_put)       CWE-22
//   - Net::SSH::Perl       ($ssh->cmd — remote command execution)            CWE-78
//   - Net::SCP            ($scp->get/put)                                    CWE-22
//
// The SFTP/SCP entries are scoped via ObjectType "Net::SFTP" / "Net::SCP";
// the tsflow matcher binds those to receivers `$sftp` / `$s` / `$scp` via the
// last-path-component + abbreviation heuristic. `$ssh->cmd` and
// `$ssh->rsync_get` use the same ObjectType-"" convention as the existing
// perl.net.openssh.* / perl.net.ssh2.exec sinks.
//
// Kept in a dedicated file to avoid the tsflow_test.go merge bottleneck.
// =========================================================================

// --- helpers ---------------------------------------------------------------

func perlSFTPFlow(t *testing.T, code string, want taint.SinkCategory, label string) {
	t.Helper()
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, want) {
		t.Errorf("expected %s flow for %s", want, label)
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Net::SFTP::Foreign — positive cases
// =========================================================================

func TestPerl_SFTP_Get_Traversal(t *testing.T) {
	code := `
use CGI;
use Net::SFTP::Foreign;
sub fetch_artifact {
    my $cgi = CGI->new;
    my $remote = $cgi->param("path");
    my $sftp = Net::SFTP::Foreign->new("build.example.com");
    $sftp->get($remote, "/tmp/out.bin");
}
`
	perlSFTPFlow(t, code, taint.SnkFileRead, "$cgi->param -> $sftp->get()")
}

func TestPerl_SFTP_Put_Traversal(t *testing.T) {
	code := `
use CGI;
use Net::SFTP::Foreign;
sub upload_artifact {
    my $cgi = CGI->new;
    my $dest = $cgi->param("dest");
    my $sftp = Net::SFTP::Foreign->new("deploy.example.com");
    $sftp->put("/tmp/build.tar.gz", $dest);
}
`
	perlSFTPFlow(t, code, taint.SnkFileWrite, "$cgi->param -> $sftp->put()")
}

func TestPerl_SFTP_GetContent_Traversal(t *testing.T) {
	code := `
use CGI;
use Net::SFTP::Foreign;
sub read_remote {
    my $cgi = CGI->new;
    my $remote = $cgi->param("file");
    my $sftp = Net::SFTP::Foreign->new("host");
    my $data = $sftp->get_content($remote);
}
`
	perlSFTPFlow(t, code, taint.SnkFileRead, "$cgi->param -> $sftp->get_content()")
}

func TestPerl_SFTP_PutContent_Traversal(t *testing.T) {
	code := `
use CGI;
use Net::SFTP::Foreign;
sub write_remote {
    my $cgi = CGI->new;
    my $remote = $cgi->param("file");
    my $sftp = Net::SFTP::Foreign->new("host");
    $sftp->put_content("hello", $remote);
}
`
	perlSFTPFlow(t, code, taint.SnkFileWrite, "$cgi->param -> $sftp->put_content()")
}

func TestPerl_SFTP_Mget_Traversal(t *testing.T) {
	code := `
use CGI;
use Net::SFTP::Foreign;
sub fetch_many {
    my $cgi = CGI->new;
    my $pattern = $cgi->param("glob");
    my $sftp = Net::SFTP::Foreign->new("host");
    $sftp->mget($pattern, "/tmp/dl");
}
`
	perlSFTPFlow(t, code, taint.SnkFileRead, "$cgi->param -> $sftp->mget()")
}

func TestPerl_SFTP_Mput_Traversal(t *testing.T) {
	code := `
use CGI;
use Net::SFTP::Foreign;
sub send_many {
    my $cgi = CGI->new;
    my $remotedir = $cgi->param("dir");
    my $sftp = Net::SFTP::Foreign->new("host");
    $sftp->mput("/tmp/up/*", $remotedir);
}
`
	perlSFTPFlow(t, code, taint.SnkFileWrite, "$cgi->param -> $sftp->mput()")
}

func TestPerl_SFTP_Rget_Traversal(t *testing.T) {
	code := `
use CGI;
use Net::SFTP::Foreign;
sub mirror_down {
    my $cgi = CGI->new;
    my $remotedir = $cgi->param("dir");
    my $sftp = Net::SFTP::Foreign->new("host");
    $sftp->rget($remotedir, "/tmp/mirror");
}
`
	perlSFTPFlow(t, code, taint.SnkFileRead, "$cgi->param -> $sftp->rget()")
}

func TestPerl_SFTP_Rput_Traversal(t *testing.T) {
	code := `
use CGI;
use Net::SFTP::Foreign;
sub mirror_up {
    my $cgi = CGI->new;
    my $remotedir = $cgi->param("dir");
    my $sftp = Net::SFTP::Foreign->new("host");
    $sftp->rput("/tmp/src", $remotedir);
}
`
	perlSFTPFlow(t, code, taint.SnkFileWrite, "$cgi->param -> $sftp->rput()")
}

func TestPerl_SFTP_Ls_Traversal(t *testing.T) {
	code := `
use CGI;
use Net::SFTP::Foreign;
sub list_dir {
    my $cgi = CGI->new;
    my $remotedir = $cgi->param("dir");
    my $sftp = Net::SFTP::Foreign->new("host");
    my $entries = $sftp->ls($remotedir);
}
`
	perlSFTPFlow(t, code, taint.SnkFileRead, "$cgi->param -> $sftp->ls()")
}

func TestPerl_SFTP_Remove_Traversal(t *testing.T) {
	code := `
use CGI;
use Net::SFTP::Foreign;
sub delete_remote {
    my $cgi = CGI->new;
    my $remote = $cgi->param("file");
    my $sftp = Net::SFTP::Foreign->new("host");
    $sftp->remove($remote);
}
`
	perlSFTPFlow(t, code, taint.SnkFileWrite, "$cgi->param -> $sftp->remove()")
}

func TestPerl_SFTP_Rremove_Traversal(t *testing.T) {
	code := `
use CGI;
use Net::SFTP::Foreign;
sub purge_remote {
    my $cgi = CGI->new;
    my $remotedir = $cgi->param("dir");
    my $sftp = Net::SFTP::Foreign->new("host");
    $sftp->rremove([$remotedir]);
}
`
	perlSFTPFlow(t, code, taint.SnkFileWrite, "$cgi->param -> $sftp->rremove()")
}

func TestPerl_SFTP_Setstat_Traversal(t *testing.T) {
	code := `
use CGI;
use Net::SFTP::Foreign;
sub chmod_remote {
    my $cgi = CGI->new;
    my $remote = $cgi->param("file");
    my $sftp = Net::SFTP::Foreign->new("host");
    $sftp->setstat($remote, perm => 0644);
}
`
	perlSFTPFlow(t, code, taint.SnkFileWrite, "$cgi->param -> $sftp->setstat()")
}

// =========================================================================
// Net::OpenSSH — rsync_get
// =========================================================================

func TestPerl_OpenSSH_RsyncGet_Traversal(t *testing.T) {
	code := `
use CGI;
use Net::OpenSSH;
sub sync_down {
    my $cgi = CGI->new;
    my $remote = $cgi->param("path");
    my $ssh = Net::OpenSSH->new("host");
    $ssh->rsync_get($remote, "/tmp/local");
}
`
	perlSFTPFlow(t, code, taint.SnkFileRead, "$cgi->param -> $ssh->rsync_get()")
}

// =========================================================================
// Net::SSH::Perl / Net::Telnet — remote command execution
// =========================================================================

func TestPerl_SSHPerl_Cmd_RCE(t *testing.T) {
	code := `
use CGI;
use Net::SSH::Perl;
sub run_remote {
    my $cgi = CGI->new;
    my $command = $cgi->param("cmd");
    my $ssh = Net::SSH::Perl->new("host");
    my @out = $ssh->cmd($command);
}
`
	perlSFTPFlow(t, code, taint.SnkCommand, "$cgi->param -> $ssh->cmd()")
}

// =========================================================================
// Net::SCP — object interface
// =========================================================================

func TestPerl_SCP_Get_Traversal(t *testing.T) {
	code := `
use CGI;
use Net::SCP;
sub scp_down {
    my $cgi = CGI->new;
    my $remote = $cgi->param("path");
    my $scp = Net::SCP->new("host");
    $scp->get($remote, "/tmp/out");
}
`
	perlSFTPFlow(t, code, taint.SnkFileRead, "$cgi->param -> $scp->get()")
}

func TestPerl_SCP_Put_Traversal(t *testing.T) {
	code := `
use CGI;
use Net::SCP;
sub scp_up {
    my $cgi = CGI->new;
    my $dest = $cgi->param("dest");
    my $scp = Net::SCP->new("host");
    $scp->put("/tmp/local", $dest);
}
`
	perlSFTPFlow(t, code, taint.SnkFileWrite, "$cgi->param -> $scp->put()")
}

// =========================================================================
// Negative cases — constant paths / no source → no flow
// =========================================================================

func TestPerl_SFTP_ConstantPaths_NoFlow(t *testing.T) {
	code := `
use Net::SFTP::Foreign;
sub deploy_static {
    my $sftp = Net::SFTP::Foreign->new("deploy.example.com");
    $sftp->put("/tmp/build.tar.gz", "/srv/releases/build.tar.gz");
    $sftp->get("/srv/config/app.conf", "/tmp/app.conf");
    $sftp->remove("/srv/releases/old.tar.gz");
}
`
	flows := Analyze(code, "/app/deploy.pl", rules.LangPerl)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileWrite || f.Sink.Category == taint.SnkFileRead {
			t.Errorf("unexpected %s flow on constant SFTP paths: %s -> %s", f.Sink.Category, f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPerl_SSHPerl_Cmd_ConstantCommand_NoFlow(t *testing.T) {
	code := `
use Net::SSH::Perl;
sub healthcheck {
    my $ssh = Net::SSH::Perl->new("host");
    my @out = $ssh->cmd("uptime");
}
`
	flows := Analyze(code, "/app/health.pl", rules.LangPerl)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("unexpected SnkCommand flow on constant remote command")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// =========================================================================
// Catalog registration
// =========================================================================

func TestPerl_SSHSFTP_SinksRegistered(t *testing.T) {
	want := map[string]bool{
		"perl.net.openssh.rsync_get": false,
		"perl.net.sftp.get":          false,
		"perl.net.sftp.put":          false,
		"perl.net.sftp.get_content":  false,
		"perl.net.sftp.put_content":  false,
		"perl.net.sftp.mget":         false,
		"perl.net.sftp.mput":         false,
		"perl.net.sftp.rget":         false,
		"perl.net.sftp.rput":         false,
		"perl.net.sftp.ls":           false,
		"perl.net.sftp.remove":       false,
		"perl.net.sftp.rremove":      false,
		"perl.net.sftp.setstat":      false,
		"perl.net.sshperl.cmd":       false,
		"perl.net.scp.get":           false,
		"perl.net.scp.put":           false,
	}
	cat := taint.GetCatalog(rules.LangPerl)
	for _, s := range cat.Sinks() {
		if _, ok := want[s.ID]; ok {
			want[s.ID] = true
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("sink %q not registered in Perl catalog", id)
		}
	}
}
