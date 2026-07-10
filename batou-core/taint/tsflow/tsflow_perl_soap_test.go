// Tests for SOAP::Lite SSRF sinks (CWE-918).
//
// SOAP::Lite is one of the longest-lived Perl modules on CPAN and is still
// bundled with many enterprise Perl services that sit behind reverse proxies.
// proxy()/endpoint() set the SOAP server URL that subsequent method dispatches
// POST to; service() loads a WSDL document from a user-controlled URL. All
// three are SSRF if the URL flows from user input.
//
// uri() is intentionally NOT a sink — per the SOAP::Lite docs it sets the XML
// namespace URN, not the request endpoint, and does not trigger an outbound
// HTTP request on its own.

package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// --- proxy() — instance form (most common in real Perl SOAP code) ---

func TestPerl_SOAPLite_Proxy_Instance_SSRF(t *testing.T) {
	code := `
use CGI;
use SOAP::Lite;
sub handler {
    my $cgi = CGI->new;
    my $url = $cgi->param("endpoint");
    my $soap = SOAP::Lite->new;
    $soap->proxy($url);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for $cgi->param -> $soap->proxy()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

// --- proxy() — class-method form ---

func TestPerl_SOAPLite_Proxy_ClassMethod_SSRF(t *testing.T) {
	code := `
use CGI;
use SOAP::Lite;
sub handler {
    my $cgi = CGI->new;
    my $url = $cgi->param("endpoint");
    my $soap = SOAP::Lite->proxy($url);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for $cgi->param -> SOAP::Lite->proxy()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

// --- endpoint() — instance form ---

func TestPerl_SOAPLite_Endpoint_Instance_SSRF(t *testing.T) {
	code := `
use CGI;
use SOAP::Lite;
sub handler {
    my $cgi = CGI->new;
    my $url = $cgi->param("ep");
    my $soap = SOAP::Lite->new;
    $soap->endpoint($url);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for $cgi->param -> $soap->endpoint()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

// --- service() — WSDL fetch (HTTP GET to user-controlled URL) ---

func TestPerl_SOAPLite_Service_WSDL_SSRF(t *testing.T) {
	code := `
use CGI;
use SOAP::Lite;
sub handler {
    my $cgi = CGI->new;
    my $wsdl_url = $cgi->param("wsdl");
    my $soap = SOAP::Lite->new;
    $soap->service($wsdl_url);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for $cgi->param -> $soap->service() (WSDL fetch)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

// --- service() — class-method form ---

func TestPerl_SOAPLite_Service_ClassMethod_SSRF(t *testing.T) {
	code := `
use CGI;
use SOAP::Lite;
sub handler {
    my $cgi = CGI->new;
    my $wsdl_url = $cgi->param("wsdl");
    my $client = SOAP::Lite->service($wsdl_url);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for $cgi->param -> SOAP::Lite->service()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

// --- ENV-source form (covers a different source seed path) ---

func TestPerl_SOAPLite_Proxy_Env_SSRF(t *testing.T) {
	code := `
use SOAP::Lite;
sub handler {
    my $url = $ENV{REMOTE_SOAP};
    my $soap = SOAP::Lite->new;
    $soap->proxy($url);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for $ENV -> $soap->proxy()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

// --- Negative test: uri() is NOT a sink (XML namespace, not endpoint) ---

func TestPerl_SOAPLite_URI_NotASink(t *testing.T) {
	code := `
use CGI;
use SOAP::Lite;
sub handler {
    my $cgi = CGI->new;
    my $ns = $cgi->param("ns");
    my $soap = SOAP::Lite->new;
    $soap->uri($ns);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("uri() should NOT be a SSRF sink — it sets the XML namespace URN, not the endpoint")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Safe form: hardcoded URL (no taint) ---

func TestPerl_SOAPLite_Proxy_Hardcoded_NoFlow(t *testing.T) {
	code := `
use SOAP::Lite;
sub handler {
    my $soap = SOAP::Lite->new;
    $soap->proxy("https://api.example.com/soap");
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("hardcoded URL should not trigger SSRF flow")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}
