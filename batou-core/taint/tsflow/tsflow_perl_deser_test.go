package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Perl deserialization source tests — second-order injection via
// deserialized data flowing to dangerous sinks (CWE-502)
// =========================================================================

func TestPerl_Storable_Thaw_Source_To_Command(t *testing.T) {
	code := `
use Storable qw(thaw);
sub handler {
    my $blob = get_from_db();
    my $cmd = thaw($blob);
    system($cmd);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from thaw() -> system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPerl_Storable_Retrieve_Source_To_Eval(t *testing.T) {
	code := `
use Storable qw(retrieve);
sub handler {
    my $code = retrieve("/tmp/cache.dat");
    eval $code;
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval injection flow from retrieve() -> eval")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPerl_Sereal_Decode_Func_Source_To_Command(t *testing.T) {
	code := `
use Sereal qw(decode_sereal);
sub handler {
    my $cmd = decode_sereal($blob);
    system($cmd);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from decode_sereal -> system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPerl_Sereal_Decode_Func_Source_To_SQL(t *testing.T) {
	code := `
use Sereal qw(decode_sereal);
use DBI;
sub handler {
    my $query = decode_sereal($blob);
    my $dbi = DBI->connect("dbi:Pg:dbname=app", "", "");
    $dbi->do($query);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from decode_sereal -> $dbh->do()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPerl_MessagePack_Func_Source_To_Eval(t *testing.T) {
	code := `
use Data::MessagePack qw(unpack_msgpack);
sub handler {
    my $code = unpack_msgpack($raw_bytes);
    eval $code;
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval injection flow from unpack_msgpack -> eval")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPerl_XMLSimple_Source_To_SQL(t *testing.T) {
	code := `
use XML::Simple;
use DBI;
sub handler {
    my $query = XMLin("/var/data/config.xml");
    my $dbi = DBI->connect("dbi:Pg:dbname=app", "", "");
    $dbi->do($query);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from XMLin -> $dbh->do()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPerl_CBOR_Decode_Func_Source_To_Command(t *testing.T) {
	code := `
use CBOR::XS qw(decode_cbor);
sub handler {
    my $cmd = decode_cbor($raw);
    system($cmd);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from decode_cbor -> system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Sink tests: CBOR and Storable::fd_retrieve ---

func TestPerl_CBOR_Decode_Sink_From_CGI(t *testing.T) {
	code := `
use CGI;
use CBOR::XS qw(decode_cbor);
sub handler {
    my $cgi = CGI->new;
    my $raw = $cgi->param("data");
    my $obj = decode_cbor($raw);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization sink flow for decode_cbor with CGI input")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPerl_Storable_FdRetrieve_Sink(t *testing.T) {
	code := `
use CGI;
use Storable qw(fd_retrieve);
sub handler {
    my $cgi = CGI->new;
    my $path = $cgi->param("file");
    my $data = fd_retrieve($path);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization sink flow for fd_retrieve with user input")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Sanitizer test: CBOR safe mode ---

func TestPerl_CBOR_Safe_Mode_Sanitizes(t *testing.T) {
	code := `
use CBOR::XS;
use CGI;
sub handler {
    my $cgi = CGI->new;
    my $raw = $cgi->param("data");
    my $cbor = CBOR::XS->new->allow_tags(0);
    my $data = $cbor->decode($raw);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize && f.Confidence > 0.7 {
			t.Error("expected CBOR::XS->allow_tags(0) to sanitize deserialization flow")
		}
	}
}

// --- Safe counterpart: deserialized data used safely ---

func TestPerl_Storable_Thaw_Sanitized_Via_Parameterized(t *testing.T) {
	code := `
use Storable qw(thaw);
use DBI;
sub handler {
    my $user_id = thaw($blob);
    my $dbh = DBI->connect("dbi:Pg:dbname=app", "", "");
    my $sth = $dbh->prepare("SELECT * FROM users WHERE id = ?");
    $sth->execute($user_id);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Confidence > 0.7 {
			t.Error("expected parameterized query to sanitize thaw -> SQL flow")
		}
	}
}
