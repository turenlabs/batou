package perlast

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

func scanPerl(t *testing.T, code string) []rules.Finding {
	t.Helper()
	tree := ast.Parse([]byte(code), rules.LangPerl)
	ctx := &rules.ScanContext{
		FilePath: "/app/cgi.pl",
		Content:  code,
		Language: rules.LangPerl,
		Tree:     tree,
	}
	a := &PerlASTAnalyzer{}
	return a.Scan(ctx)
}

func hasFinding(findings []rules.Finding, ruleID, cwe string) *rules.Finding {
	for i := range findings {
		if findings[i].RuleID == ruleID && findings[i].CWEID == cwe {
			return &findings[i]
		}
	}
	return nil
}

func TestSystemCommandInjection(t *testing.T) {
	code := `my $host = $cgi->param("host");
system("ping $host");
`
	f := hasFinding(scanPerl(t, code), "BATOU-PERL-AST-001", "CWE-78")
	if f == nil {
		t.Fatal("expected CWE-78 system() command injection finding")
	}
	if f.Severity != rules.Critical {
		t.Errorf("expected Critical, got %s", f.Severity)
	}
}

func TestExecCommandInjection(t *testing.T) {
	// External origin: @ARGV is a CLI-argument source in the allowlist.
	code := `my $p = $ARGV[0];
exec("$p --run");
`
	if hasFinding(scanPerl(t, code), "BATOU-PERL-AST-001", "CWE-78") == nil {
		t.Fatal("expected CWE-78 exec() command injection finding")
	}
}

func TestBacktickInjection(t *testing.T) {
	code := "my $cmd = $cgi->param('cmd');\nmy $out = `ls $cmd`;\n"
	if hasFinding(scanPerl(t, code), "BATOU-PERL-AST-002", "CWE-78") == nil {
		t.Fatal("expected CWE-78 backtick command injection finding")
	}
}

func TestQxInjection(t *testing.T) {
	code := "my $u = $req->param('user');\nmy $z = qx/whoami $u/;\n"
	if hasFinding(scanPerl(t, code), "BATOU-PERL-AST-002", "CWE-78") == nil {
		t.Fatal("expected CWE-78 qx// command injection finding")
	}
}

func TestTwoArgOpenPathTraversal(t *testing.T) {
	code := `my $f = $cgi->param("f");
open(FH, "> $f");
`
	f := hasFinding(scanPerl(t, code), "BATOU-PERL-AST-003", "CWE-22")
	if f == nil {
		t.Fatal("expected CWE-22 2-arg open path traversal finding")
	}
}

func TestTwoArgOpenVariableFilename(t *testing.T) {
	code := `my $name = $cgi->param("name");
open(my $fh, $name);
`
	if hasFinding(scanPerl(t, code), "BATOU-PERL-AST-003", "CWE-22") == nil {
		t.Fatal("expected CWE-22 2-arg open finding for variable filename")
	}
}

func TestPipedOpenCommandInjection(t *testing.T) {
	code := `my $cmd = $cgi->param('cmd');
open(P, "$cmd |");
`
	if hasFinding(scanPerl(t, code), "BATOU-PERL-AST-003", "CWE-78") == nil {
		t.Fatal("expected CWE-78 piped open command injection finding")
	}
}

func TestSubstEvalCodeExec(t *testing.T) {
	code := `my $expr = $cgi->param('expr');
my $t = "x";
$t =~ s/(\w+)/$expr/ge;
`
	f := hasFinding(scanPerl(t, code), "BATOU-PERL-AST-004", "CWE-94")
	if f == nil {
		t.Fatal("expected CWE-94 s///e code execution finding")
	}
	if f.Severity != rules.Critical {
		t.Errorf("expected Critical, got %s", f.Severity)
	}
}

// --- False-positive guards ---

func TestSafeThreeArgOpenNoFinding(t *testing.T) {
	code := `my $path = $cgi->param("p");
open(my $fh, "<", $path) or die;
`
	for _, f := range scanPerl(t, code) {
		if strings.HasPrefix(f.RuleID, "BATOU-PERL-AST") {
			t.Errorf("safe 3-arg open should not fire AST, got %s", f.RuleID)
		}
	}
}

func TestSafeListFormSystemNoFinding(t *testing.T) {
	// List form bypasses the shell; no shell-interpolated string.
	code := `my $p = $cgi->param("p");
system("ping", "-c", "1", $p);
`
	for _, f := range scanPerl(t, code) {
		if f.RuleID == "BATOU-PERL-AST-001" {
			t.Errorf("list-form system() should not fire AST, got %s", f.RuleID)
		}
	}
}

func TestLiteralCommandNoFinding(t *testing.T) {
	code := "system(\"ls -la\");\nmy $d = `date`;\n"
	for _, f := range scanPerl(t, code) {
		if strings.HasPrefix(f.RuleID, "BATOU-PERL-AST") {
			t.Errorf("literal command should not fire AST, got %s", f.RuleID)
		}
	}
}

func TestSubstNoEvalNoFinding(t *testing.T) {
	code := `my $x = $form{x};
my $t = "abc";
$t =~ s/(\w+)/[$x]/g;
`
	for _, f := range scanPerl(t, code) {
		if f.RuleID == "BATOU-PERL-AST-004" {
			t.Errorf("substitution without /e should not fire AST, got %s", f.RuleID)
		}
	}
}

func TestSubstEvalConstantReplacementNoFinding(t *testing.T) {
	code := `my $t = "abc";
$t =~ s/(\d+)/2+2/ge;
`
	for _, f := range scanPerl(t, code) {
		if f.RuleID == "BATOU-PERL-AST-004" {
			t.Errorf("s///e with constant replacement should not fire AST, got %s", f.RuleID)
		}
	}
}

func TestNonPerlLanguageIgnored(t *testing.T) {
	code := `system("ping $host");`
	tree := ast.Parse([]byte(code), rules.LangPerl)
	ctx := &rules.ScanContext{
		FilePath: "/app/x.py",
		Content:  code,
		Language: rules.LangPython, // wrong language → analyzer must no-op
		Tree:     tree,
	}
	a := &PerlASTAnalyzer{}
	if got := a.Scan(ctx); got != nil {
		t.Errorf("analyzer must return nil for non-Perl language, got %d findings", len(got))
	}
}

// --- External-origin gating (the precision rework) ---

// External data flowing through a hand-rolled %FORM hash (populated from
// $ENV{'QUERY_STRING'}) must still be recognised as external — the taint
// catalog does not model %FORM, which is the gap this analyzer closes.
func TestExternalViaHandRolledHash(t *testing.T) {
	code := `my %FORM;
foreach my $pair (split /&/, $ENV{'QUERY_STRING'} // '') {
    my ($k, $v) = split /=/, $pair, 2;
    $FORM{$k} = $v;
}
my $host = $FORM{'host'};
system("ping -c 1 $host");
`
	if hasFinding(scanPerl(t, code), "BATOU-PERL-AST-001", "CWE-78") == nil {
		t.Fatal("expected system() finding for external data via hand-rolled FORM hash")
	}
}

// Local/constant data reaching the same dangerous shape must NOT fire — this is
// the flood the rework eliminates. system() over a locally-derived path is safe.
func TestLocalDataSystemNoFinding(t *testing.T) {
	code := `my $prefix = "/opt/app";
my $name = "report.txt";
system("ls $prefix/$name");
`
	for _, f := range scanPerl(t, code) {
		if f.RuleID == "BATOU-PERL-AST-001" {
			t.Errorf("local-data system() must NOT fire after gating, got %s", f.RuleID)
		}
	}
}

// Regression for the AST-003 Mojo flood: the LIST / exec form
// `open my $fh, '-|', $^X, $prog, @args` does NOT pass through a shell and must
// NEVER be flagged — even though the '-|' mode arg contains a pipe.
func TestListFormPipedOpenNoFinding(t *testing.T) {
	code := `my $prefix = curfile->dirname->sibling('script');
my $script = "app.pl";
open my $start, '-|', $^X, "$prefix/hypnotoad", $script;
`
	for _, f := range scanPerl(t, code) {
		if f.RuleID == "BATOU-PERL-AST-003" {
			t.Errorf("list-form piped open() must NOT fire (not shell-injectable), got %s", f.RuleID)
		}
	}
}

// Even with external data, the LIST form is not shell-injectable and must not
// fire — the safety is structural (direct exec), independent of origin.
func TestListFormPipedOpenExternalNoFinding(t *testing.T) {
	code := `my $script = $cgi->param('script');
open my $start, '-|', $^X, "/opt/run", $script;
`
	for _, f := range scanPerl(t, code) {
		if f.RuleID == "BATOU-PERL-AST-003" {
			t.Errorf("list-form open() must NOT fire even with external arg, got %s", f.RuleID)
		}
	}
}

// Regression for the AST-004 Mojo flood (Mojo::Util::_html): an s///e whose
// replacement is a FIXED function call over regex captures / static args
// (_entity($1, $2, $attr)) is NOT eval injection and must NOT fire.
func TestSubstEvalFixedFuncCallNoFinding(t *testing.T) {
	code := `my $ENTITY_RE = qr/(\w+);/;
sub _html {
    my ($str, $attr) = @_;
    $str =~ s/$ENTITY_RE/_entity($1, $2, $attr)/geo;
    return $str;
}
`
	for _, f := range scanPerl(t, code) {
		if f.RuleID == "BATOU-PERL-AST-004" {
			t.Errorf("s///e with a fixed function-call replacement must NOT fire, got %s", f.RuleID)
		}
	}
}

// A bare-scalar /e replacement that IS external code still fires.
func TestSubstEvalBareScalarExternalFinding(t *testing.T) {
	code := `my $expr = $ENV{'EXPR'};
my $t = "input";
$t =~ s/(\w+)/$expr/ge;
`
	if hasFinding(scanPerl(t, code), "BATOU-PERL-AST-004", "CWE-94") == nil {
		t.Fatal("expected s///e finding for external bare-scalar replacement")
	}
}
