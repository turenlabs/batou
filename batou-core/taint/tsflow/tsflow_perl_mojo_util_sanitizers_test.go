package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Perl — Mojo::Util output-encoding sanitizers (Mojolicious).
//
// Companions to the existing perl.mojo.util.xml_escape entry:
//   - url_escape  : percent-encodes -> SnkRedirect / SnkHeader / SnkHTMLOutput
//   - term_escape : escapes terminal control chars -> SnkLog
//   - slugify     : [a-z0-9-] allowlist -> SnkCommand / SnkSQLQuery / SnkFile* / SnkHTMLOutput
//
// Per-feature file (not appended to tsflow_test.go) to keep the merge-conflict
// surface minimal. Each sanitizer test pairs a tainted CGI source with the new
// sanitizer and asserts the relevant sink-category flow is NOT produced; the
// trailing "Unsanitized" regression tests confirm the same source/sink pair
// WOULD flow without the sanitizer — guarding the silent-pass failure mode.
// =========================================================================

// --- Mojo::Util::url_escape (SnkRedirect) ---

func TestPerl_MojoUtil_UrlEscape_SanitizesRedirect(t *testing.T) {
	code := `
use CGI;
use Mojo::Util qw(url_escape);
sub handler {
    my $cgi = CGI->new;
    my $next = $cgi->param("next");
    my $safe = Mojo::Util::url_escape($next);
    return $cgi->redirect($safe);
}
`
	flows := Analyze(code, "/app/redirect.pl", rules.LangPerl)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect && f.Confidence > 0.7 {
			t.Errorf("expected Mojo::Util::url_escape to sanitize redirect flow, got conf %.2f", f.Confidence)
		}
	}
}

// --- Mojo::Util::term_escape (SnkLog) ---

func TestPerl_MojoUtil_TermEscape_SanitizesLog(t *testing.T) {
	code := `
use CGI;
use Mojo::Util qw(term_escape);
sub handler {
    my $cgi = CGI->new;
    my $name = $cgi->param("name");
    my $safe = Mojo::Util::term_escape($name);
    my $log = Mojo::Log->new;
    $log->info($safe);
}
`
	flows := Analyze(code, "/app/audit.pl", rules.LangPerl)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLog && f.Confidence > 0.7 {
			t.Errorf("expected Mojo::Util::term_escape to sanitize log flow, got conf %.2f", f.Confidence)
		}
	}
}

// --- Mojo::Util::slugify (SnkCommand) ---

func TestPerl_MojoUtil_Slugify_SanitizesCommand(t *testing.T) {
	code := `
use CGI;
use Mojo::Util qw(slugify);
sub handler {
    my $cgi = CGI->new;
    my $title = $cgi->param("title");
    my $slug = Mojo::Util::slugify($title);
    system($slug);
}
`
	flows := Analyze(code, "/app/render.pl", rules.LangPerl)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand && f.Confidence > 0.7 {
			t.Errorf("expected Mojo::Util::slugify to sanitize command flow, got conf %.2f", f.Confidence)
		}
	}
}

// --- Negative regression checks: unsanitized flows MUST still fire ---

func TestPerl_MojoUtil_Redirect_Unsanitized(t *testing.T) {
	code := `
use CGI;
sub handler {
    my $cgi = CGI->new;
    my $next = $cgi->param("next");
    return $cgi->redirect($next);
}
`
	flows := Analyze(code, "/app/redirect.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected SnkRedirect flow for unsanitized $next -> $cgi->redirect (regression check)")
	}
}

func TestPerl_MojoUtil_Log_Unsanitized(t *testing.T) {
	code := `
use CGI;
sub handler {
    my $cgi = CGI->new;
    my $name = $cgi->param("name");
    my $log = Mojo::Log->new;
    $log->info($name);
}
`
	flows := Analyze(code, "/app/audit.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected SnkLog flow for unsanitized $name -> $log->info (regression check)")
	}
}

func TestPerl_MojoUtil_Command_Unsanitized(t *testing.T) {
	code := `
use CGI;
sub handler {
    my $cgi = CGI->new;
    my $title = $cgi->param("title");
    system($title);
}
`
	flows := Analyze(code, "/app/render.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for unsanitized $title -> system (regression check)")
	}
}
