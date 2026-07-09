package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Perl — sanitizer additions covering crypto, XSS, redirect, and SSRF gaps.
//
// Per-feature file (not appended to tsflow_test.go) to keep the
// merge-conflict surface minimal — the long-running taint-research loop
// continues to churn _sinks/_sources changes across every language and
// tsflow_test.go is the most contested test file.
//
// Each test pairs a tainted user-input source with the new sanitizer and
// asserts the relevant sink-category flow is NOT produced. Negative
// counterparts confirm the same source/sink pair WOULD flow without the
// sanitizer in place — guarding against the silent-pass failure mode where
// a sanitizer test "passes" only because the chosen sink never fires.
// =========================================================================

// --- Crypt::OpenSSL::Random (SnkCrypto) ---

func TestPerl_CryptOpenSSLRandom_SanitizesCrypto(t *testing.T) {
	code := `
use CGI;
use Crypt::OpenSSL::Random;
use Digest::MD4 qw(md4_hex);
sub handler {
    my $cgi = CGI->new;
    my $size = $cgi->param("size");
    my $bytes = Crypt::OpenSSL::Random::random_bytes($size);
    return md4_hex($bytes);
}
`
	flows := Analyze(code, "/app/random.pl", rules.LangPerl)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto && f.Confidence > 0.7 {
			t.Errorf("expected Crypt::OpenSSL::Random::random_bytes to sanitize crypto flow, got conf %.2f", f.Confidence)
		}
	}
}

// --- Net::IDN::Encode (SnkRedirect, SnkURLFetch) ---

func TestPerl_NetIDNEncode_DomainToAscii_SanitizesRedirect(t *testing.T) {
	code := `
use CGI;
use Net::IDN::Encode;
sub handler {
    my $cgi = CGI->new;
    my $host = $cgi->param("host");
    my $puny = Net::IDN::Encode::domain_to_ascii($host);
    return $cgi->redirect($puny);
}
`
	flows := Analyze(code, "/app/redirect.pl", rules.LangPerl)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect && f.Confidence > 0.7 {
			t.Errorf("expected Net::IDN::Encode::domain_to_ascii to sanitize redirect flow, got conf %.2f", f.Confidence)
		}
	}
}

func TestPerl_NetIDNEncode_DomainToAscii_SanitizesURLFetch(t *testing.T) {
	code := `
use CGI;
use Net::IDN::Encode;
use LWP::Simple;
sub handler {
    my $cgi = CGI->new;
    my $host = $cgi->param("host");
    my $puny = Net::IDN::Encode::domain_to_ascii($host);
    return getstore($puny, "/tmp/out");
}
`
	flows := Analyze(code, "/app/fetch.pl", rules.LangPerl)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch && f.Confidence > 0.7 {
			t.Errorf("expected Net::IDN::Encode::domain_to_ascii to sanitize URLFetch flow, got conf %.2f", f.Confidence)
		}
	}
}

// --- URI::Encode (SnkRedirect) ---

func TestPerl_URIEncode_UriEncode_SanitizesRedirect(t *testing.T) {
	code := `
use CGI;
use URI::Encode;
sub handler {
    my $cgi = CGI->new;
    my $next = $cgi->param("next");
    my $safe = URI::Encode::uri_encode($next);
    return $cgi->redirect($safe);
}
`
	flows := Analyze(code, "/app/redirect.pl", rules.LangPerl)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect && f.Confidence > 0.7 {
			t.Errorf("expected URI::Encode::uri_encode to sanitize redirect flow, got conf %.2f", f.Confidence)
		}
	}
}

// --- HTML::Restrict (SnkHTMLOutput) ---

func TestPerl_HTMLRestrict_Process_SanitizesXSS(t *testing.T) {
	code := `
use CGI;
use HTML::Restrict;
sub handler {
    my $cgi = CGI->new;
    my $bio = $cgi->param("bio");
    my $clean = HTML::Restrict->process($bio);
    return $cgi->start_html($clean);
}
`
	flows := Analyze(code, "/app/render.pl", rules.LangPerl)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Confidence > 0.7 {
			t.Errorf("expected HTML::Restrict->process to sanitize XSS flow, got conf %.2f", f.Confidence)
		}
	}
}

// --- HTML::Defang (SnkHTMLOutput) ---

func TestPerl_HTMLDefang_Defang_SanitizesXSS(t *testing.T) {
	code := `
use CGI;
use HTML::Defang;
sub handler {
    my $cgi = CGI->new;
    my $body = $cgi->param("comment");
    my $clean = HTML::Defang->defang($body);
    return $cgi->start_html($clean);
}
`
	flows := Analyze(code, "/app/comments.pl", rules.LangPerl)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Confidence > 0.7 {
			t.Errorf("expected HTML::Defang->defang to sanitize XSS flow, got conf %.2f", f.Confidence)
		}
	}
}

// --- Negative regression checks: unsanitized flows MUST still fire ---

func TestPerl_Sanitizers_Crypto_Unsanitized(t *testing.T) {
	code := `
use CGI;
use Digest::MD4 qw(md4_hex);
sub handler {
    my $cgi = CGI->new;
    my $pass = $cgi->param("password");
    return md4_hex($pass);
}
`
	flows := Analyze(code, "/app/auth.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected SnkCrypto flow for unsanitized password -> md4_hex (regression check)")
	}
}

func TestPerl_Sanitizers_Redirect_Unsanitized(t *testing.T) {
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

func TestPerl_Sanitizers_URLFetch_Unsanitized(t *testing.T) {
	code := `
use CGI;
use LWP::Simple;
sub handler {
    my $cgi = CGI->new;
    my $host = $cgi->param("host");
    return getstore($host, "/tmp/out");
}
`
	flows := Analyze(code, "/app/fetch.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SnkURLFetch flow for unsanitized $host -> getstore (regression check)")
	}
}

func TestPerl_Sanitizers_HTML_Unsanitized(t *testing.T) {
	code := `
use CGI;
sub handler {
    my $cgi = CGI->new;
    my $bio = $cgi->param("bio");
    return $cgi->start_html($bio);
}
`
	flows := Analyze(code, "/app/render.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected SnkHTMLOutput flow for unsanitized $bio -> $cgi->start_html (regression check)")
	}
}

