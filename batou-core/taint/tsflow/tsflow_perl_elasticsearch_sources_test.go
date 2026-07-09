package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Perl — Search::Elasticsearch / OpenSearch::Client read-back sources
// (second-order stored-injection, SrcDatabase).
//
// The write side (perl.elasticsearch.bulk / msearch / delete_by_query /
// update_by_query / reindex / put_script / search_template) was already
// modeled as SnkNoSQL / SnkEval sinks, but the documents returned BACK out
// of the cluster were never treated as taint sources. A value an untrusted
// user indexed on one request is echoed verbatim inside the `_source` of a
// later search / get / mget / scroll response; concatenating that document
// into a command / SQL / eval sink is a stored-injection (second-order)
// flow that previously went undetected.
//
// Sources are scoped via ObjectType "Search::Elasticsearch" so the matcher
// last-part abbreviation heuristic fires only for receiver names that are a
// prefix of "elasticsearch" — the canonical documented handle `$e` (used
// verbatim in the perl.elasticsearch.* sink descriptions) plus `$elastic` /
// `$elasticsearch`. Net::LDAP's $ldap->search and Redis's $r->mget use
// receiver names that are NOT prefixes of "elasticsearch", so they do not
// collide (see the negative regressions below).
//
// Kept in a dedicated file to avoid the tsflow_test.go merge bottleneck.
// =========================================================================

func TestPerl_Elasticsearch_Search_SecondOrder_Command(t *testing.T) {
	code := `
use Search::Elasticsearch;
sub handler {
    my $e = Search::Elasticsearch->new( nodes => 'localhost:9200' );
    my $docs = $e->search( index => 'users', body => { query => { match_all => {} } } );
    return system("echo " . $docs);
}
`
	flows := Analyze(code, "/app/h.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $e->search -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPerl_Elasticsearch_Search_ElasticReceiver_SecondOrder_Command(t *testing.T) {
	code := `
use Search::Elasticsearch;
sub handler {
    my $elastic = Search::Elasticsearch->new( nodes => 'localhost:9200' );
    my $docs = $elastic->search( index => 'users', body => { query => { match_all => {} } } );
    return system("/usr/bin/run " . $docs);
}
`
	flows := Analyze(code, "/app/h.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $elastic->search -> system")
	}
}

func TestPerl_Elasticsearch_Get_SecondOrder_Command(t *testing.T) {
	code := `
use Search::Elasticsearch;
sub handler {
    my $e = Search::Elasticsearch->new( nodes => 'localhost:9200' );
    my $doc = $e->get( index => 'users', id => 42 );
    return system("echo " . $doc);
}
`
	flows := Analyze(code, "/app/h.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $e->get -> system")
	}
}

func TestPerl_Elasticsearch_Mget_SecondOrder_Command(t *testing.T) {
	code := `
use Search::Elasticsearch;
sub handler {
    my $e = Search::Elasticsearch->new( nodes => 'localhost:9200' );
    my $docs = $e->mget( index => 'users', body => { ids => [1, 2, 3] } );
    return system("echo " . $docs);
}
`
	flows := Analyze(code, "/app/h.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $e->mget -> system")
	}
}

func TestPerl_Elasticsearch_Scroll_SecondOrder_Command(t *testing.T) {
	code := `
use Search::Elasticsearch;
sub handler {
    my $e = Search::Elasticsearch->new( nodes => 'localhost:9200' );
    my $batch = $e->scroll( scroll => '1m', scroll_id => 'abc' );
    return system("echo " . $batch);
}
`
	flows := Analyze(code, "/app/h.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $e->scroll -> system")
	}
}

// ---- Cross-store stored injection: ES read -> DBI SQL sink -------------

func TestPerl_Elasticsearch_Search_To_SQLi(t *testing.T) {
	code := `
use Search::Elasticsearch;
use DBI;
sub handler {
    my $dbi = DBI->connect('dbi:Pg:dbname=app');
    my $e = Search::Elasticsearch->new( nodes => 'localhost:9200' );
    my $docs = $e->search( index => 'users', body => { query => { match_all => {} } } );
    $dbi->do("SELECT * FROM logs WHERE note = '" . $docs . "'");
}
`
	flows := Analyze(code, "/app/h.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SnkSQLQuery flow for $e->search -> DBI->do")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ---- Negative regression: non-Elasticsearch receiver must NOT match ----
// Net::LDAP's $ldap->search shares the method name "search" but the
// receiver "ldap" is not a prefix of "elasticsearch", so the ES source
// must not fire here as a SrcDatabase flow.

func TestPerl_Elasticsearch_LdapSearch_NoDatabaseFlow(t *testing.T) {
	code := `
use Net::LDAP;
sub handler {
    my $ldap = Net::LDAP->new('ldap://localhost');
    my $res = $ldap->search( base => 'dc=x', filter => '(objectClass=*)' );
    return system("echo " . $res);
}
`
	flows := Analyze(code, "/app/h.pl", rules.LangPerl)
	for _, f := range flows {
		if f.Source.ID == "perl.elasticsearch.search" {
			t.Errorf("did not expect perl.elasticsearch.search to match $ldap->search, got %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// ---- Negative regression: constant value through same call shape -------

func TestPerl_Elasticsearch_Constant_NoFlow(t *testing.T) {
	code := `
sub handler {
    my $docs = "constant-string";
    return system("echo " . $docs);
}
`
	flows := Analyze(code, "/app/h.pl", rules.LangPerl)
	for _, f := range flows {
		if f.Source.Category == taint.SrcDatabase && f.Sink.Category == taint.SnkCommand {
			t.Errorf("did not expect SrcDatabase flow for constant string assignment, got %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}
