package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Perl — Search::Elasticsearch / OpenSearch::Client query-DSL + Painless
// injection (CWE-943, CWE-94).
//
// Search::Elasticsearch is the official Perl client. Its high-level methods
// take a `body =>` named argument that becomes the JSON / NDJSON request body
// — tainted values inside the body permit query-structure manipulation
// (filter bypass, cross-index exfiltration) and, for endpoints accepting a
// `script.source` field, Painless code execution on the cluster.
//
// Mirrors go.elasticsearch.*, kotlin.elasticsearch.*, ruby.elasticsearch.*,
// js.elasticsearch.*.
//
// Kept in a dedicated file to avoid the tsflow_test.go merge bottleneck.
// =========================================================================

// $e->bulk(body => $tainted_ndjson) — DSL injection across mixed
// index/update/delete actions.
func TestPerl_Elasticsearch_Bulk_TaintedBody(t *testing.T) {
	code := `
use CGI;
use Search::Elasticsearch;
sub handler {
    my $cgi  = CGI->new;
    my $body = $cgi->param("payload");
    my $e    = Search::Elasticsearch->new;
    return $e->bulk(index => "twitter", body => $body);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected SnkSQLQuery flow for CGI param -> $e->bulk(body)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// $e->msearch(body => $tainted_ndjson) — per-shard DSL injection
// across multiple search queries.
func TestPerl_Elasticsearch_Msearch_TaintedBody(t *testing.T) {
	code := `
use CGI;
use Search::Elasticsearch;
sub handler {
    my $cgi   = CGI->new;
    my $input = $cgi->param("queries");
    my $e     = Search::Elasticsearch->new;
    return $e->msearch(body => $input);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected SnkSQLQuery flow for CGI param -> $e->msearch(body)")
	}
}

// $e->delete_by_query(body => { query => $tainted }) — destructive bulk
// operation with attacker-controlled match selector.
func TestPerl_Elasticsearch_DeleteByQuery_TaintedQuery(t *testing.T) {
	code := `
use CGI;
use Search::Elasticsearch;
sub handler {
    my $cgi   = CGI->new;
    my $input = $cgi->param("filter");
    my $e     = Search::Elasticsearch->new;
    return $e->delete_by_query(index => "logs", body => $input);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected SnkSQLQuery flow for CGI param -> $e->delete_by_query(body)")
	}
}

// $e->update_by_query(body => { script => { source => $tainted } }) —
// Painless code execution on the cluster.
func TestPerl_Elasticsearch_UpdateByQuery_TaintedScript(t *testing.T) {
	code := `
use CGI;
use Search::Elasticsearch;
sub handler {
    my $cgi    = CGI->new;
    my $script = $cgi->param("painless");
    my $e      = Search::Elasticsearch->new;
    return $e->update_by_query(index => "users", body => $script);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for CGI param -> $e->update_by_query(body)")
	}
}

// $e->reindex(body => { script => { source => $tainted } }) —
// Painless source executes on the cluster + cross-index data movement.
func TestPerl_Elasticsearch_Reindex_TaintedScript(t *testing.T) {
	code := `
use CGI;
use Search::Elasticsearch;
sub handler {
    my $cgi    = CGI->new;
    my $script = $cgi->param("painless");
    my $e      = Search::Elasticsearch->new;
    return $e->reindex(body => $script);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for CGI param -> $e->reindex(body)")
	}
}

// $e->put_script(body => { script => { source => $tainted } }) —
// stored Painless script that any later request can invoke.
func TestPerl_Elasticsearch_PutScript_TaintedSource(t *testing.T) {
	code := `
use CGI;
use Search::Elasticsearch;
sub handler {
    my $cgi    = CGI->new;
    my $script = $cgi->param("source");
    my $e      = Search::Elasticsearch->new;
    return $e->put_script(id => "calculate", body => $script);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for CGI param -> $e->put_script(body)")
	}
}

// $e->scripts_painless_execute(body => { script => { source => $tainted } })
// — ad-hoc Painless evaluation on the cluster.
func TestPerl_Elasticsearch_ScriptsPainlessExecute_TaintedSource(t *testing.T) {
	code := `
use CGI;
use Search::Elasticsearch;
sub handler {
    my $cgi    = CGI->new;
    my $script = $cgi->param("painless");
    my $e      = Search::Elasticsearch->new;
    return $e->scripts_painless_execute(body => $script);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for CGI param -> $e->scripts_painless_execute(body)")
	}
}

// $e->search_template(body => { source => $tainted_mustache }) —
// SSTI-into-DSL on the cluster.
func TestPerl_Elasticsearch_SearchTemplate_TaintedTemplate(t *testing.T) {
	code := `
use CGI;
use Search::Elasticsearch;
sub handler {
    my $cgi  = CGI->new;
    my $tpl  = $cgi->param("mustache");
    my $e    = Search::Elasticsearch->new;
    return $e->search_template(index => "products", body => $tpl);
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected SnkSQLQuery flow for CGI param -> $e->search_template(body)")
	}
}

// Negative test: hard-coded body should not produce a flow.
func TestPerl_Elasticsearch_Bulk_StaticBody_NoFlow(t *testing.T) {
	code := `
use Search::Elasticsearch;
sub handler {
    my $e = Search::Elasticsearch->new;
    return $e->bulk(index => "twitter", body => '{"index":{"_id":1}}');
}
`
	flows := Analyze(code, "/app/handler.pl", rules.LangPerl)
	for _, f := range flows {
		if f.Sink.ID == "perl.elasticsearch.bulk" {
			t.Errorf("unexpected flow for static body: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
