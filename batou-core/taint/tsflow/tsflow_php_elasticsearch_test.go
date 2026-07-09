package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// PHP elastic/elasticsearch-php + opensearch-project/opensearch-php
// query-DSL + Painless RCE injection tests (CWE-943 / CWE-94).
//
// Only ES-distinctive method names are covered here — generic names like
// ->search / ->count / ->index would FP on non-ES collections and belong
// to the regex layer if needed.
// =========================================================================

// --- msearch: NDJSON multi-search body ---

func TestPHP_Elasticsearch_MSearchBody(t *testing.T) {
	code := `<?php
function multi_search($client) {
    $term = $_GET['term'];
    $params = [
        'body' => [
            ['index' => 'logs'],
            ['query' => ['match' => ['message' => $term]]],
        ],
    ];
    return $client->msearch($params);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected DSL-injection flow for $_GET -> $client->msearch")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- deleteByQuery: mass-delete via tainted DSL ---

func TestPHP_Elasticsearch_DeleteByQuery(t *testing.T) {
	code := `<?php
function purge($client) {
    $tag = $_POST['tag'];
    return $client->deleteByQuery([
        'index' => 'items',
        'body'  => ['query' => ['match' => ['tag' => $tag]]],
    ]);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected DSL-injection flow for $_POST -> $client->deleteByQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- updateByQuery: Painless RCE via script.source ---

func TestPHP_Elasticsearch_UpdateByQueryScript(t *testing.T) {
	code := `<?php
function bulk_update($client) {
    $src = $_POST['script_source'];
    return $client->updateByQuery([
        'index' => 'items',
        'body'  => [
            'script' => ['source' => $src, 'lang' => 'painless'],
            'query'  => ['match_all' => new \stdClass()],
        ],
    ]);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected Painless RCE flow for $_POST -> $client->updateByQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- scriptsPainlessExecute: direct Painless evaluation ---

func TestPHP_Elasticsearch_ScriptsPainlessExecute(t *testing.T) {
	code := `<?php
function run_script($client) {
    $src = $_POST['source'];
    return $client->scriptsPainlessExecute([
        'body' => ['script' => ['source' => $src, 'lang' => 'painless']],
    ]);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected direct Painless RCE flow for $_POST -> $client->scriptsPainlessExecute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- putScript: stored Painless script (persistent RCE) ---

func TestPHP_Elasticsearch_PutScriptStored(t *testing.T) {
	code := `<?php
function save_script($client) {
    $src = $_POST['src'];
    return $client->putScript([
        'id'   => 'calc',
        'body' => ['script' => ['source' => $src, 'lang' => 'painless']],
    ]);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected stored-script RCE flow for $_POST -> $client->putScript")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- reindex: tainted source.query DSL ---

func TestPHP_Elasticsearch_Reindex(t *testing.T) {
	code := `<?php
function copy_docs($client) {
    $tag = $_GET['tag'];
    return $client->reindex([
        'body' => [
            'source' => [
                'index' => 'src',
                'query' => ['match' => ['tag' => $tag]],
            ],
            'dest' => ['index' => 'dst'],
        ],
    ]);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected DSL-injection flow for $_GET -> $client->reindex")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- searchTemplate: Mustache template → Painless invocation ---

func TestPHP_Elasticsearch_SearchTemplate(t *testing.T) {
	code := `<?php
function render_search($client) {
    $src = $_POST['tpl'];
    return $client->searchTemplate([
        'body' => ['source' => $src, 'params' => ['q' => 'foo']],
    ]);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected template-injection RCE flow for $_POST -> $client->searchTemplate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- OpenSearch client uses the identical API — same matcher should fire ---

func TestPHP_OpenSearch_MSearch_SameAPI(t *testing.T) {
	code := `<?php
function search($client) {
    $q = $_GET['q'];
    $params = [
        'body' => [
            ['index' => 'logs'],
            ['query' => ['query_string' => ['query' => $q]]],
        ],
    ];
    return $client->msearch($params);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected DSL-injection flow for OpenSearch client ($_GET -> msearch)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Negative: no user-input source in scope must NOT fire ES painless sinks.
// (PHP's tsflow walker treats function parameters as tainted by default, so this
// negative must exercise a handler with no parameter flowing into the call. We
// build $client locally and use only hardcoded script source / query values.)

func TestPHP_Elasticsearch_Safe_HardcodedScriptSource(t *testing.T) {
	code := `<?php
function bump() {
    $client = \Elasticsearch\ClientBuilder::create()->build();
    return $client->updateByQuery([
        'index' => 'items',
        'body'  => [
            'script' => ['source' => 'ctx._source.count++', 'lang' => 'painless'],
            'query'  => ['match_all' => new \stdClass()],
        ],
    ]);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	for _, f := range flows {
		if f.Sink.ID == "php.elasticsearch.updatebyquery" {
			t.Errorf("unexpected updateByQuery sink firing on hardcoded script source: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}
