package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Perl — Plack::Request input sources (PSGI foundational layer)
//
// Plack::Request is the wrapper around the PSGI $env that virtually every
// modern Perl web app sees, either directly (Plack apps), via Plack::Handler
// (Mojolicious PSGI mode), Catalyst::Engine::PSGI, or Dancer2's PSGI core.
//
// Existing coverage: param, body_parameters, header, cookies, plus PSGI
// query_string and psgi.input env keys. This file fills the documented
// Plack::Request API gaps: combined parameters, raw body, uploads, path,
// referer/user_agent, single cookie value, and Plack::Request::Upload.
//
// API reference: https://metacpan.org/pod/Plack::Request
//
// Kept in a dedicated file to avoid the tsflow_test.go merge bottleneck.
// =========================================================================

// $req->parameters — combined query+body params (Hash::MultiValue) flowing into system().
func TestPerl_Plack_Parameters_ToSystem(t *testing.T) {
	code := `
use Plack::Request;
sub handler {
    my $env = shift;
    my $req = Plack::Request->new($env);
    my $cmd = $req->parameters->{cmd};
    system("ls $cmd");
}
`
	flows := Analyze(code, "/app/plack.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $req->parameters -> system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// $req->query_parameters — query string params flowing into system().
func TestPerl_Plack_QueryParameters_ToSystem(t *testing.T) {
	code := `
use Plack::Request;
sub handler {
    my $env = shift;
    my $req = Plack::Request->new($env);
    my $arg = $req->query_parameters->{arg};
    system("echo $arg");
}
`
	flows := Analyze(code, "/app/plack.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $req->query_parameters -> system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// $req->raw_body — raw POST body content flowing into eval. Common JSON-API pattern.
func TestPerl_Plack_RawBody_ToEval(t *testing.T) {
	code := `
use Plack::Request;
sub handler {
    my $env  = shift;
    my $req  = Plack::Request->new($env);
    my $body = $req->raw_body;
    eval $body;
}
`
	flows := Analyze(code, "/app/plack.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for $req->raw_body -> eval")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// $req->content — alias for raw_body, same risk class.
func TestPerl_Plack_Content_ToSystem(t *testing.T) {
	code := `
use Plack::Request;
sub handler {
    my $env  = shift;
    my $req  = Plack::Request->new($env);
    my $body = $req->content;
    system("/usr/bin/process " . $body);
}
`
	flows := Analyze(code, "/app/plack.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $req->content -> system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// $req->path — URL path used directly in unlink() (path traversal CWE-22).
func TestPerl_Plack_Path_ToUnlink(t *testing.T) {
	code := `
use Plack::Request;
sub handler {
    my $env  = shift;
    my $req  = Plack::Request->new($env);
    my $path = $req->path;
    unlink("/var/www/files/" . $path);
}
`
	flows := Analyze(code, "/app/plack.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkFileWrite) && !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkFileWrite flow for $req->path -> unlink()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// $req->path_info — alternative path source flowing into system().
func TestPerl_Plack_PathInfo_ToSystem(t *testing.T) {
	code := `
use Plack::Request;
sub handler {
    my $env = shift;
    my $req = Plack::Request->new($env);
    my $p   = $req->path_info;
    system("cat /var/log/$p");
}
`
	flows := Analyze(code, "/app/plack.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $req->path_info -> system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// $req->referer — Referer header reflected into a system command (header injection / RCE).
func TestPerl_Plack_Referer_ToSystem(t *testing.T) {
	code := `
use Plack::Request;
sub handler {
    my $env = shift;
    my $req = Plack::Request->new($env);
    my $ref = $req->referer;
    system("logger 'visited from $ref'");
}
`
	flows := Analyze(code, "/app/plack.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $req->referer -> system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// $req->user_agent — User-Agent flowing into exec() (log poisoning + RCE).
func TestPerl_Plack_UserAgent_ToExec(t *testing.T) {
	code := `
use Plack::Request;
sub handler {
    my $env = shift;
    my $req = Plack::Request->new($env);
    my $ua  = $req->user_agent;
    exec("/usr/bin/uagent-tool $ua");
}
`
	flows := Analyze(code, "/app/plack.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $req->user_agent -> exec()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// $req->upload(...) — single uploaded file object flowing into system() (filename portion).
// Smoke-tests that the upload() method itself fires as a source (the returned
// Plack::Request::Upload's filename method is covered by the next test).
func TestPerl_Plack_Upload_ToSystem(t *testing.T) {
	code := `
use Plack::Request;
sub handler {
    my $env = shift;
    my $req = Plack::Request->new($env);
    my $up  = $req->upload("file");
    system("convert $up out.png");
}
`
	flows := Analyze(code, "/app/plack.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $req->upload -> system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Plack::Request::Upload->filename — client-supplied filename (path traversal source).
func TestPerl_Plack_UploadFilename_ToUnlink(t *testing.T) {
	code := `
use Plack::Request;
sub handler {
    my $env    = shift;
    my $req    = Plack::Request->new($env);
    my $upload = $req->upload("file");
    my $name   = $upload->filename;
    unlink("/tmp/uploads/" . $name);
}
`
	flows := Analyze(code, "/app/plack.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkFileWrite) && !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkFileWrite flow for $upload->filename -> unlink()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Plack::Request::Upload->basename — client-supplied basename, same path traversal class.
func TestPerl_Plack_UploadBasename_ToUnlink(t *testing.T) {
	code := `
use Plack::Request;
sub handler {
    my $env    = shift;
    my $req    = Plack::Request->new($env);
    my $upload = $req->upload("file");
    my $base   = $upload->basename;
    unlink("/tmp/uploads/" . $base);
}
`
	flows := Analyze(code, "/app/plack.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkFileWrite) && !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkFileWrite flow for $upload->basename -> unlink()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative test — a fully literal path passed to unlink/system must NOT produce
// a flow, even when a Plack request object exists in scope. Guards against
// over-broad matching of the new entries (e.g., $req binding alone shouldn't
// taint everything in the function body).
func TestPerl_Plack_LiteralPath_NoFlow(t *testing.T) {
	code := `
use Plack::Request;
sub handler {
    my $env = shift;
    my $req = Plack::Request->new($env);
    unlink("/etc/app.conf");
    system("echo hello");
}
`
	flows := Analyze(code, "/app/plack.pl", rules.LangPerl)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileWrite || f.Sink.Category == taint.SnkCommand {
			t.Errorf("unexpected %s flow for literal path: source=%s sink=%s", f.Sink.Category, f.Source.ID, f.Sink.ID)
		}
	}
}
