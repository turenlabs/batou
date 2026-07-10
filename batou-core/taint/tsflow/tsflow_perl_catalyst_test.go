package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Perl — Catalyst framework additional sinks
//
// Catalyst is one of the three major Perl web frameworks (with Mojolicious
// and Dancer2). Existing coverage was 4 sinks: redirect, body, session.set,
// flash — leaving open-redirect via Location, MIME confusion via
// content_type, response::write streaming, stash trust boundary, and
// forward/detach controller dispatch all uncovered.
//
// $c is the conventional Catalyst controller invocant. The matcher's
// HasPrefix("catalyst","c") abbreviation heuristic maps receiver "c" onto
// ObjectType "Catalyst" — the same mechanism used by the four existing
// Catalyst entries.
//
// API references:
//   https://metacpan.org/pod/Catalyst::Response
//   https://metacpan.org/pod/Catalyst::Manual::Intro#stash
//   https://metacpan.org/pod/Catalyst::Manual::Actions#forward / detach
//
// Kept in a dedicated file to avoid the tsflow_test.go merge bottleneck.
// =========================================================================

// $c->res->location with a tainted URL → open redirect via Location header.
func TestPerl_Catalyst_Res_Location_OpenRedirect(t *testing.T) {
	code := `
package MyApp::Controller::Auth;
use base 'Catalyst::Controller';
sub login :Path('/login') {
    my ($self, $c) = @_;
    my $next = $c->req->param('next');
    $c->res->location($next);
}
1;
`
	flows := Analyze(code, "/app/MyApp/Controller/Auth.pm", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected SnkRedirect flow for $c->req->param -> $c->res->location()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// $c->res->content_type with tainted MIME — content sniffing into HTML/JS.
func TestPerl_Catalyst_Res_ContentType_MimeConfusion(t *testing.T) {
	code := `
package MyApp::Controller::Files;
use base 'Catalyst::Controller';
sub serve :Local {
    my ($self, $c) = @_;
    my $mime = $c->req->param('type');
    $c->res->content_type($mime);
    $c->res->body("data");
}
1;
`
	flows := Analyze(code, "/app/MyApp/Controller/Files.pm", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected SnkHeader flow for $c->req->param -> $c->res->content_type()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// $c->res->write streams a chunk into the body — XSS via reflected unescaped data.
func TestPerl_Catalyst_Res_Write_XSS(t *testing.T) {
	code := `
package MyApp::Controller::Stream;
use base 'Catalyst::Controller';
sub stream :Local {
    my ($self, $c) = @_;
    my $name = $c->req->param('name');
    $c->res->write("<h1>Hello, $name</h1>");
}
1;
`
	flows := Analyze(code, "/app/MyApp/Controller/Stream.pm", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected SnkHTMLOutput flow for $c->req->param -> $c->res->write()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// $c->stash(key => $tainted) call form — trust boundary into TT/Mason.
func TestPerl_Catalyst_Stash_Call_TrustBoundary(t *testing.T) {
	code := `
package MyApp::Controller::Profile;
use base 'Catalyst::Controller';
sub view :Local {
    my ($self, $c) = @_;
    my $bio = $c->req->param('bio');
    $c->stash(bio => $bio, template => 'profile.tt');
}
1;
`
	flows := Analyze(code, "/app/MyApp/Controller/Profile.pm", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected SnkTrustBoundary flow for $c->req->param -> $c->stash()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// $c->forward($action_name) with tainted action name → arbitrary controller dispatch.
func TestPerl_Catalyst_Forward_CodePathInjection(t *testing.T) {
	code := `
package MyApp::Controller::Dispatcher;
use base 'Catalyst::Controller';
sub dispatch :Local {
    my ($self, $c) = @_;
    my $action = $c->req->param('action');
    $c->forward($action);
}
1;
`
	flows := Analyze(code, "/app/MyApp/Controller/Dispatcher.pm", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for $c->req->param -> $c->forward()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// $c->detach($action_name) with tainted action name → like forward but no return.
func TestPerl_Catalyst_Detach_CodePathInjection(t *testing.T) {
	code := `
package MyApp::Controller::Dispatcher;
use base 'Catalyst::Controller';
sub dispatch :Local {
    my ($self, $c) = @_;
    my $target = $c->req->param('target');
    $c->detach($target);
}
1;
`
	flows := Analyze(code, "/app/MyApp/Controller/Dispatcher.pm", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for $c->req->param -> $c->detach()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative: hardcoded constants must NOT produce a flow — guards against
// over-broad Catalyst entries firing on idiomatic constant calls.
func TestPerl_Catalyst_Constants_NoFlow(t *testing.T) {
	code := `
package MyApp::Controller::Static;
use base 'Catalyst::Controller';
sub home :Path('/') {
    my ($self, $c) = @_;
    $c->res->location('/welcome');
    $c->res->content_type('text/html');
    $c->res->write("<h1>Welcome</h1>");
    $c->stash(template => 'home.tt');
    $c->forward('Auth::login');
    $c->detach('Auth::logout');
}
1;
`
	flows := Analyze(code, "/app/MyApp/Controller/Static.pm", rules.LangPerl)
	for _, f := range flows {
		switch f.Sink.ID {
		case "perl.catalyst.res.location",
			"perl.catalyst.res.content_type",
			"perl.catalyst.res.write",
			"perl.catalyst.stash.call",
			"perl.catalyst.forward",
			"perl.catalyst.detach":
			t.Errorf("unexpected catalyst flow on constant arg: sink=%s source=%s",
				f.Sink.ID, f.Source.ID)
		}
	}
}
