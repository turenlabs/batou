package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Perl — additional IPC / process-spawn command injection (CWE-78)
//
// Covers three widely used IPC modules that were not yet in the catalog:
// IPC::Run3::run3, AnyEvent::Util::run_cmd, and Proc::Background->new.
// Kept in a dedicated file to avoid the tsflow_test.go merge bottleneck.
// =========================================================================

// IPC::Run3 run3() executes a command whose first argument may be a
// tainted scalar or a list containing tainted elements.
func TestPerl_Cmd_IPCRun3_Run3_Tainted(t *testing.T) {
	code := `
use CGI;
use IPC::Run3;
sub handler {
    my $cgi = CGI->new;
    my $input = $cgi->param("cmd");
    IPC::Run3::run3($input);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for CGI param -> IPC::Run3::run3()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Bare run3() — the function is imported into the caller's namespace via
// `use IPC::Run3` so the call appears without the module prefix.
func TestPerl_Cmd_IPCRun3_BareRun3_Tainted(t *testing.T) {
	code := `
use CGI;
use IPC::Run3;
sub handler {
    my $cgi = CGI->new;
    my $input = $cgi->param("cmd");
    run3($input);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for CGI param -> bare run3()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// AnyEvent::Util::run_cmd() — async child spawn. When called with a scalar
// the argument is parsed by the shell, so tainted input is directly
// injectable.
func TestPerl_Cmd_AnyEventUtil_RunCmd_Tainted(t *testing.T) {
	code := `
use CGI;
use AnyEvent::Util qw(run_cmd);
sub handler {
    my $cgi = CGI->new;
    my $input = $cgi->param("cmd");
    my $cv = AnyEvent::Util::run_cmd($input);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for CGI param -> AnyEvent::Util::run_cmd()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Proc::Background->new($cmd) — starts a background process whose command
// line is the constructor argument. Tainted scalar input is shell-parsed.
func TestPerl_Cmd_ProcBackground_New_Tainted(t *testing.T) {
	code := `
use CGI;
use Proc::Background;
sub handler {
    my $cgi = CGI->new;
    my $input = $cgi->param("cmd");
    my $proc = Proc::Background->new($input);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for CGI param -> Proc::Background->new()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
