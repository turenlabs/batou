package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Perl — DBI SQL-injection sinks on the canonical `$dbh` database handle.
//
// DBI's own POD and virtually all real-world Perl bind the database handle
// to `$dbh` (`my $dbh = DBI->connect(...)`). The taint catalog scopes the
// DBI SQL sinks (do / prepare / prepare_cached) to ObjectType "DBI", but the
// tsflow receiver matcher only direct-matched the unusual spelling `$dbi`
// ("dbh" is neither equal to nor a prefix of "dbi"). As a result the most
// common DBI injection shape — `$dbh->do("... $userinput ...")` — produced
// ZERO tsflow findings. These tests pin the `$dbh`/`$dbc` receiver alias
// (matcher.go) plus the new prepare_cached sink.
//
// Kept in a dedicated file to avoid the tsflow_test.go merge bottleneck.
// =========================================================================

func TestPerl_DBI_Do_Dbh_SQLi(t *testing.T) {
	code := `
use CGI;
use DBI;
sub handler {
    my $cgi = CGI->new;
    my $name = $cgi->param("name");
    my $dbh = DBI->connect("dbi:Pg:dbname=app", "", "");
    $dbh->do("SELECT * FROM users WHERE name = '" . $name . "'");
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from $cgi->param -> $dbh->do()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPerl_DBI_Prepare_Dbh_SQLi(t *testing.T) {
	code := `
use CGI;
use DBI;
sub handler {
    my $cgi = CGI->new;
    my $name = $cgi->param("name");
    my $dbh = DBI->connect("dbi:Pg:dbname=app", "", "");
    my $sth = $dbh->prepare("SELECT * FROM users WHERE name = '" . $name . "'");
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from $cgi->param -> $dbh->prepare()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPerl_DBI_PrepareCached_Dbh_SQLi(t *testing.T) {
	code := `
use CGI;
use DBI;
sub handler {
    my $cgi = CGI->new;
    my $name = $cgi->param("name");
    my $dbh = DBI->connect("dbi:Pg:dbname=app", "", "");
    my $sth = $dbh->prepare_cached("SELECT * FROM users WHERE name = '" . $name . "'");
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from $cgi->param -> $dbh->prepare_cached()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Alias variant: handle bound to `$dbc` (another common DBI handle name).
func TestPerl_DBI_Do_Dbc_Alias_SQLi(t *testing.T) {
	code := `
use CGI;
use DBI;
sub handler {
    my $cgi = CGI->new;
    my $name = $cgi->param("name");
    my $dbc = DBI->connect("dbi:Pg:dbname=app", "", "");
    $dbc->do("DELETE FROM users WHERE name = '" . $name . "'");
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from $cgi->param -> $dbc->do()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative regression: a constant SQL string through the same call shape must
// NOT produce a SQL-injection flow (no tainted source reaches the sink).
func TestPerl_DBI_Do_Constant_NoFlow(t *testing.T) {
	code := `
use DBI;
sub handler {
    my $dbh = DBI->connect("dbi:Pg:dbname=app", "", "");
    $dbh->do("SELECT 1");
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Confidence > 0.7 {
			t.Errorf("did not expect SQL flow for constant query, got %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}
