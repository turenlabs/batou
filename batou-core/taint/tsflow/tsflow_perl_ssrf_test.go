package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// Perl SSRF / URL-fetch sink coverage expansion (CWE-918).
//
// The existing Perl catalog only covered a subset of HTTP verbs on each client
// library. These tests exercise the additional entries for LWP::Simple helpers,
// LWP::UserAgent mirror/head, the remaining Mojo::UserAgent verbs, and the
// HTTP::Request constructor.
//
// The receiver variables match the last path component of the ObjectType
// (e.g., "$useragent" for "LWP::UserAgent") because the tsflow matcher uses
// a HasPrefix abbreviation heuristic. "$ua" is more common in real Perl code
// but does NOT currently match "useragent" — that gap affects every Perl
// SSRF sink (not just the new ones) and is out of scope for this PR.

// --- LWP::Simple::getstore ---
// Bare function — no receiver needed. Distinctive name, no FP risk.

func TestPerl_LWPSimple_Getstore_SSRF(t *testing.T) {
	code := `
use CGI;
use LWP::Simple;
sub handler {
    my $cgi = CGI->new;
    my $url = $cgi->param("url");
    my $rc = getstore($url, "/tmp/out.html");
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for $cgi->param -> getstore()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- LWP::Simple::getprint ---

func TestPerl_LWPSimple_Getprint_SSRF(t *testing.T) {
	code := `
use CGI;
use LWP::Simple;
sub handler {
    my $cgi = CGI->new;
    my $url = $cgi->param("url");
    getprint($url);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for $cgi->param -> getprint()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- LWP::UserAgent->mirror ---

func TestPerl_LWPUA_Mirror_SSRF(t *testing.T) {
	code := `
use CGI;
use LWP::UserAgent;
sub handler {
    my $cgi = CGI->new;
    my $url = $cgi->param("src");
    my $useragent = LWP::UserAgent->new;
    $useragent->mirror($url, "/tmp/mirror.html");
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for $cgi->param -> $useragent->mirror()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- LWP::UserAgent->head ---

func TestPerl_LWPUA_Head_SSRF(t *testing.T) {
	code := `
use CGI;
use LWP::UserAgent;
sub handler {
    my $cgi = CGI->new;
    my $url = $cgi->param("target");
    my $useragent = LWP::UserAgent->new;
    my $resp = $useragent->head($url);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for $cgi->param -> $useragent->head()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Mojo::UserAgent->head ---

func TestPerl_MojoUA_Head_SSRF(t *testing.T) {
	code := `
use Mojolicious::Lite;
use Mojo::UserAgent;
sub handler {
    my ($c) = @_;
    my $url = $c->param("target");
    my $useragent = Mojo::UserAgent->new;
    my $tx = $useragent->head($url);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for $c->param -> Mojo $useragent->head()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Mojo::UserAgent->put ---

func TestPerl_MojoUA_Put_SSRF(t *testing.T) {
	code := `
use Mojolicious::Lite;
use Mojo::UserAgent;
sub handler {
    my ($c) = @_;
    my $url = $c->param("dest");
    my $useragent = Mojo::UserAgent->new;
    my $tx = $useragent->put($url, json => {foo => 1});
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for $c->param -> Mojo $useragent->put()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Mojo::UserAgent->delete ---

func TestPerl_MojoUA_Delete_SSRF(t *testing.T) {
	code := `
use Mojolicious::Lite;
use Mojo::UserAgent;
sub handler {
    my ($c) = @_;
    my $url = $c->param("dest");
    my $useragent = Mojo::UserAgent->new;
    my $tx = $useragent->delete($url);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for $c->param -> Mojo $useragent->delete()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Mojo::UserAgent->patch ---

func TestPerl_MojoUA_Patch_SSRF(t *testing.T) {
	code := `
use Mojolicious::Lite;
use Mojo::UserAgent;
sub handler {
    my ($c) = @_;
    my $url = $c->param("dest");
    my $useragent = Mojo::UserAgent->new;
    my $tx = $useragent->patch($url, json => {foo => 1});
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for $c->param -> Mojo $useragent->patch()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Mojo::UserAgent->build_tx ---
// The URL is at arg 1 (arg 0 is the HTTP method name).

func TestPerl_MojoUA_BuildTx_SSRF(t *testing.T) {
	code := `
use Mojolicious::Lite;
use Mojo::UserAgent;
sub handler {
    my ($c) = @_;
    my $url = $c->param("dest");
    my $useragent = Mojo::UserAgent->new;
    my $tx = $useragent->build_tx(GET => $url);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for $c->param -> Mojo $useragent->build_tx()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- HTTP::Request->new ---
// Class-method call — receiver is "HTTP::Request" (a bareword), which
// matches catObjectType "HTTP::Request" exactly via the direct name check.

func TestPerl_HTTPRequest_New_SSRF(t *testing.T) {
	code := `
use CGI;
use HTTP::Request;
use LWP::UserAgent;
sub handler {
    my $cgi = CGI->new;
    my $url = $cgi->param("target");
    my $req = HTTP::Request->new(GET => $url);
    my $useragent = LWP::UserAgent->new;
    my $resp = $useragent->request($req);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for $cgi->param -> HTTP::Request->new()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Negative: hardcoded URL should not flag as SSRF ---

func TestPerl_LWPSimple_Getstore_HardcodedURL_NoFlow(t *testing.T) {
	code := `
use LWP::Simple;
sub handler {
    my $rc = getstore("https://internal.example/static.html", "/tmp/out.html");
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch && f.Confidence > 0.7 {
			t.Errorf("unexpected SSRF flow for hardcoded URL into getstore(): %+v", f)
		}
	}
}
