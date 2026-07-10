package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Perl SSTI / template-injection tests (CWE-1336)
// Covers: Mojo::Template render_file, Text::MicroTemplate render_mt/build_mt,
// HTML::Mason $m->comp / $m->scomp
// =========================================================================

func TestPerl_MojoTemplate_RenderFile_SSTI(t *testing.T) {
	code := `
use CGI;
use Mojo::Template;
sub handler {
    my $cgi = CGI->new;
    my $tpl_path = $cgi->param("template");
    my $mt = Mojo::Template->new;
    $mt->render_file($tpl_path);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected template injection flow for $cgi->param -> Mojo::Template->render_file()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPerl_MicroTemplate_RenderMt_SSTI(t *testing.T) {
	code := `
use CGI;
use Text::MicroTemplate qw(render_mt);
sub handler {
    my $cgi = CGI->new;
    my $tpl = $cgi->param("template");
    my $html = render_mt($tpl)->as_string;
    return $html;
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected template injection flow for $cgi->param -> render_mt()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPerl_MicroTemplate_BuildMt_SSTI(t *testing.T) {
	code := `
use CGI;
use Text::MicroTemplate qw(build_mt);
sub handler {
    my $cgi = CGI->new;
    my $tpl = $cgi->param("template");
    my $renderer = build_mt($tpl);
    return $renderer->()->as_string;
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected template injection flow for $cgi->param -> build_mt()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPerl_Mason_Comp_ComponentInjection(t *testing.T) {
	code := `
use CGI;
sub handler {
    my $cgi = CGI->new;
    my $comp_path = $cgi->param("page");
    $m->comp($comp_path);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected template/component injection flow for $cgi->param -> $m->comp()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPerl_Mason_Scomp_ComponentInjection(t *testing.T) {
	code := `
use CGI;
sub handler {
    my $cgi = CGI->new;
    my $comp_path = $cgi->param("widget");
    my $html = $m->scomp($comp_path);
    return $html;
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected template/component injection flow for $cgi->param -> $m->scomp()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative: a hard-coded constant template path should NOT produce a taint flow.
func TestPerl_MojoTemplate_RenderFile_ConstantPath_NoFlow(t *testing.T) {
	code := `
use Mojo::Template;
sub handler {
    my $mt = Mojo::Template->new;
    $mt->render_file("/etc/app/templates/index.mt");
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTemplate && f.Confidence > 0.7 {
			t.Error("did not expect template injection flow for constant render_file() path")
		}
	}
}
