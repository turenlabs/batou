package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Perl XSLT injection tests (XML::LibXSLT, XML::XSLT) — CWE-91
// =========================================================================
//
// Untrusted XSLT stylesheets enable arbitrary file read via document(),
// network access via xsl:include / xsl:import, and command execution
// through EXSLT extensions (str:tokenize, exsl:document). Treat the
// stylesheet body or its source path as code.

// parse_stylesheet receives a tainted XML::LibXML::Document built from
// CGI input — attacker fully controls the XSLT body.
func TestPerl_XML_LibXSLT_ParseStylesheet_TaintFlow(t *testing.T) {
	code := `
use CGI;
use XML::LibXML;
use XML::LibXSLT;
sub handler {
    my $cgi = CGI->new;
    my $xsl_text = $cgi->param("stylesheet");
    my $parser = XML::LibXML->new();
    my $xslt = XML::LibXSLT->new();
    my $style_doc = $parser->parse_string($xsl_text);
    my $stylesheet = $xslt->parse_stylesheet($style_doc);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XSLT-injection flow: $cgi->param -> XML::LibXSLT->parse_stylesheet")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// parse_stylesheet_file accepts a tainted file path — attacker can point
// at a hostile XSLT located via SSRF, NFS, or a writable temp dir.
func TestPerl_XML_LibXSLT_ParseStylesheetFile_TaintFlow(t *testing.T) {
	code := `
use CGI;
use XML::LibXSLT;
sub handler {
    my $cgi = CGI->new;
    my $sheet_path = $cgi->param("sheet");
    my $xslt = XML::LibXSLT->new();
    my $stylesheet = $xslt->parse_stylesheet_file($sheet_path);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XSLT-injection flow: $cgi->param -> parse_stylesheet_file")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// transform_file applies a stylesheet to a tainted source XML path —
// enables path traversal and XSLT-side data access against arbitrary files.
func TestPerl_XML_LibXSLT_TransformFile_TaintFlow(t *testing.T) {
	code := `
use CGI;
use XML::LibXSLT;
sub handler {
    my $cgi = CGI->new;
    my $src = $cgi->param("xml_source");
    my $xslt = XML::LibXSLT->new();
    my $stylesheet = $xslt->parse_stylesheet_file("/srv/trusted.xsl");
    my $results = $stylesheet->transform_file($src);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XSLT-injection flow: $cgi->param -> $stylesheet->transform_file")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// XML::XSLT (pure-Perl processor) takes the stylesheet body in its
// constructor — first arg fully controls the XSL document.
func TestPerl_XML_XSLT_New_TaintFlow(t *testing.T) {
	code := `
use CGI;
use XML::XSLT;
sub handler {
    my $cgi = CGI->new;
    my $xsl = $cgi->param("xsl");
    my $parser = XML::XSLT->new($xsl, warnings => 1);
    my $output = $parser->serve("<doc/>");
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XSLT-injection flow: $cgi->param -> XML::XSLT->new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative test: when the stylesheet path is a hardcoded literal there is
// no source -> sink chain, so no XSLT-injection flow should be reported.
// The XML::LibXSLT::Security sanitizer is a separate catalog mitigation
// marker (parallel to libxslt's xsltSetSecurityPrefs in the C catalog) —
// presence in the catalog documents the trust-boundary control even though
// taint engines without object-state tracking cannot model it directly.
func TestPerl_XML_LibXSLT_HardcodedPath_NoFlow(t *testing.T) {
	code := `
use XML::LibXSLT;
use XML::LibXSLT::Security;
sub handler {
    my $xslt = XML::LibXSLT->new();
    my $security = XML::LibXSLT::Security->new();
    $security->register_callback(XML::LibXSLT::Security::READ_FILE, sub { 0 });
    $xslt->security_callbacks($security);
    my $stylesheet = $xslt->parse_stylesheet_file("/srv/known/style.xsl");
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkXPath {
			t.Errorf("expected NO XSLT-injection flow when stylesheet path is hardcoded; got: %s -> %s (conf: %.2f)",
				f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
