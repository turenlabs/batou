package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Perl — top-level / script-body taint flows (CWE-78, CWE-22)
//
// The dominant real Perl/CGI idiom is a flat script body with NO enclosing
// sub{}: a CGI parameter read at file scope flows directly into system() or
// open(). Before the LangPerl top-level pass in walkTree, the walker only
// analyzed statements inside subroutine declarations, so these flat scripts
// produced ZERO flows. These tests pin the fix.
// =========================================================================

// $cgi->param(...) -> system(...) at file scope (no sub wrapper).
func TestPerl_TopLevel_CGIParam_System(t *testing.T) {
	code := `#!/usr/bin/perl
use CGI;
my $cgi = CGI->new;
my $input = $cgi->param("cmd");
system($input);
`
	flows := Analyze(code, "/var/www/cgi-bin/run.cgi", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for top-level $cgi->param -> system()")
	}
	assertHighConfidence(t, flows, taint.SnkCommand)
}

// Top-level exec($tainted) — second CWE-78 command sink at file scope.
func TestPerl_TopLevel_CGIParam_Exec(t *testing.T) {
	code := `#!/usr/bin/perl
use CGI;
my $cgi = CGI->new;
my $cmd = $cgi->param("cmd");
exec($cmd);
`
	flows := Analyze(code, "/var/www/cgi-bin/exec.cgi", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for top-level $cgi->param -> exec()")
	}
	assertHighConfidence(t, flows, taint.SnkCommand)
}

// $cgi->param(...) -> open(FH, MODE, $tainted) at file scope (CWE-22).
// The tainted path is the 3rd argument of open(), so this also exercises
// the perl.open sink scanning all arguments (DangerousArgs -1) rather than
// only arg 0 (the file handle).
func TestPerl_TopLevel_CGIParam_Open(t *testing.T) {
	code := `#!/usr/bin/perl
use CGI;
my $cgi = CGI->new;
my $file = $cgi->param("file");
open(my $fh, ">", $file);
`
	flows := Analyze(code, "/var/www/cgi-bin/upload.cgi", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected SnkFileWrite flow for top-level $cgi->param -> open()")
	}
	assertHighConfidence(t, flows, taint.SnkFileWrite)
}

// Regression guard: a sub-scoped flow must STILL be detected after adding the
// top-level pass (the per-function walk is unchanged).
func TestPerl_SubScoped_StillDetected(t *testing.T) {
	code := `#!/usr/bin/perl
use CGI;
sub handler {
    my $cgi = CGI->new;
    my $input = $cgi->param("cmd");
    system($input);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for sub-scoped $cgi->param -> system()")
	}
}

// Negative guard: a top-level script with a constant (non-tainted) argument
// must NOT produce a command-injection flow.
func TestPerl_TopLevel_ConstArg_NoFlow(t *testing.T) {
	code := `#!/usr/bin/perl
use CGI;
my $cgi = CGI->new;
system("/bin/true");
`
	flows := Analyze(code, "/var/www/cgi-bin/safe.cgi", rules.LangPerl)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("did not expect SnkCommand flow for top-level system() with constant arg")
	}
}

// assertHighConfidence fails the test unless at least one flow into the given
// sink category was reported at high (>= 0.7) confidence. This documents that
// the top-level pass produces taint-confirmed flows, not low-confidence noise.
func assertHighConfidence(t *testing.T, flows []taint.TaintFlow, cat taint.SinkCategory) {
	t.Helper()
	for _, f := range flows {
		if f.Sink.Category == cat && f.Confidence >= 0.7 {
			return
		}
	}
	t.Errorf("expected a high-confidence (>=0.7) flow into %s; flows: %+v", cat, flows)
}
