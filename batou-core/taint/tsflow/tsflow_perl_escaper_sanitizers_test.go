package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Perl — escaper sanitizer completions for two canonical modules that were
// only half-covered on main:
//
//   - URI::Escape::uri_escape_utf8   (sibling of uri_escape; UTF-8 variant)
//   - String::ShellQuote::shell_quote_best_effort (sibling of shell_quote)
//
// Per-feature file (not appended to tsflow_test.go) to keep the
// merge-conflict surface minimal.
//
// Each new sanitizer gets a positive test (tainted source → sanitizer →
// sink asserts the relevant category flow is NOT produced) plus a negative
// control proving the same source/sink pair WOULD flow without the
// sanitizer — guarding against the silent-pass failure mode where the test
// "passes" only because the chosen sink never fires.
// =========================================================================

// --- URI::Escape::uri_escape_utf8 (SnkRedirect) ---

func TestPerl_URIEscapeUtf8_SanitizesRedirect(t *testing.T) {
	code := `
use CGI;
use URI::Escape;
sub handler {
    my $cgi = CGI->new;
    my $next = $cgi->param("next");
    my $safe = uri_escape_utf8($next);
    return $cgi->redirect($safe);
}
`
	flows := Analyze(code, "/app/redirect.pl", rules.LangPerl)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect && f.Confidence > 0.7 {
			t.Errorf("expected uri_escape_utf8 to sanitize redirect flow, got conf %.2f", f.Confidence)
		}
	}
}

// Negative control: without uri_escape_utf8 the redirect flow must fire.
func TestPerl_URIEscapeUtf8_NegativeControl_RedirectFlows(t *testing.T) {
	code := `
use CGI;
sub handler {
    my $cgi = CGI->new;
    my $next = $cgi->param("next");
    return $cgi->redirect($next);
}
`
	flows := Analyze(code, "/app/redirect_vuln.pl", rules.LangPerl)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect {
			found = true
		}
	}
	if !found {
		t.Errorf("negative control failed: expected an unsanitized SnkRedirect flow, got none (sink never fired — positive test is meaningless)")
	}
}

// --- String::ShellQuote::shell_quote_best_effort (SnkCommand) ---

func TestPerl_ShellQuoteBestEffort_SanitizesCommand(t *testing.T) {
	code := `
use CGI;
use String::ShellQuote;
sub handler {
    my $cgi = CGI->new;
    my $name = $cgi->param("name");
    my $safe = shell_quote_best_effort($name);
    system("ls $safe");
}
`
	flows := Analyze(code, "/app/cmd.pl", rules.LangPerl)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand && f.Confidence > 0.7 {
			t.Errorf("expected shell_quote_best_effort to sanitize command flow, got conf %.2f", f.Confidence)
		}
	}
}

// Negative control: without shell_quote_best_effort the command flow must fire.
func TestPerl_ShellQuoteBestEffort_NegativeControl_CommandFlows(t *testing.T) {
	code := `
use CGI;
sub handler {
    my $cgi = CGI->new;
    my $name = $cgi->param("name");
    system("ls $name");
}
`
	flows := Analyze(code, "/app/cmd_vuln.pl", rules.LangPerl)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand {
			found = true
		}
	}
	if !found {
		t.Errorf("negative control failed: expected an unsanitized SnkCommand flow, got none (sink never fired — positive test is meaningless)")
	}
}

// Registration check — confirm the two new sanitizer IDs are loaded.
func TestPerl_EscaperSanitizers_Registered(t *testing.T) {
	want := map[string]bool{
		"perl.uri.escape_utf8":               false,
		"perl.string.shellquote_best_effort": false,
	}
	for _, s := range taint.SanitizersForLanguage(rules.LangPerl) {
		if _, ok := want[s.ID]; ok {
			want[s.ID] = true
		}
	}
	for id, seen := range want {
		if !seen {
			t.Errorf("sanitizer %q not registered for Perl", id)
		}
	}
}
