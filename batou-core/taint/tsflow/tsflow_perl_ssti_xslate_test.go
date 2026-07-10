package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Perl SSTI / template-injection tests (CWE-1336) — additional engines
// Covers: Text::Xslate render_string, Text::Template functional interface
// (fill_in_string / fill_in_file).
// =========================================================================

func TestPerl_Xslate_RenderString_SSTI(t *testing.T) {
	code := `
use CGI;
use Text::Xslate;
sub handler {
    my $cgi = CGI->new;
    my $tpl = $cgi->param("template");
    my $xslate = Text::Xslate->new;
    my $out = $xslate->render_string($tpl, { name => "world" });
    return $out;
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected template injection flow for $cgi->param -> Text::Xslate->render_string()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPerl_TextTemplate_FillInString_SSTI(t *testing.T) {
	code := `
use CGI;
use Text::Template qw(fill_in_string);
sub handler {
    my $cgi = CGI->new;
    my $tpl = $cgi->param("template");
    my $out = fill_in_string($tpl, HASH => { user => "alice" });
    return $out;
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected template injection flow for $cgi->param -> fill_in_string()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPerl_TextTemplate_FillInFile_SSTI(t *testing.T) {
	code := `
use CGI;
use Text::Template qw(fill_in_file);
sub handler {
    my $cgi = CGI->new;
    my $tpl_path = $cgi->param("page");
    my $out = fill_in_file($tpl_path, HASH => { user => "alice" });
    return $out;
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected template injection flow for $cgi->param -> fill_in_file()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative: a hard-coded constant template string should NOT produce a taint flow.
func TestPerl_Xslate_RenderString_ConstantTemplate_NoFlow(t *testing.T) {
	code := `
use Text::Xslate;
sub handler {
    my $xslate = Text::Xslate->new;
    my $out = $xslate->render_string("<: \$name :>", { name => "world" });
    return $out;
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTemplate && f.Confidence > 0.7 {
			t.Error("did not expect template injection flow for constant render_string() template")
		}
	}
}
