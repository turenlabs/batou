package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Ruby — Elasticsearch / OpenSearch (elasticsearch-ruby + opensearch-ruby)
// DSL injection (CWE-943) + Painless RCE (CWE-94).
// =========================================================================
// Covers the seven ES/OS Ruby client entries in ruby_sinks.go:
//   - ruby.elasticsearch.msearch
//   - ruby.elasticsearch.delete_by_query
//   - ruby.elasticsearch.update_by_query
//   - ruby.elasticsearch.scripts_painless_execute
//   - ruby.elasticsearch.put_script
//   - ruby.elasticsearch.reindex
//   - ruby.elasticsearch.search_template
// Only ES/OS-unique method names are exercised — generic .search()/.index()/
// .update()/.bulk() are out of scope (FP risk on ActiveRecord/Mongo/etc.).
// All tests use a `def handler(params)` source signature, the Ruby
// param-propagation convention required by the tsflow walker.

func TestRuby_Elasticsearch_MSearchBody_DSLInjection(t *testing.T) {
	code := `
require "elasticsearch"

def multi_search(params)
  term = params[:term]
  client = Elasticsearch::Client.new
  body = [
    { index: "logs" },
    { query: { match: { message: term } } },
  ]
  client.msearch(body: body)
end
`
	flows := Analyze(code, "/app/controllers/search_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected DSL injection flow for params -> Elasticsearch client.msearch")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_Elasticsearch_DeleteByQuery_DSLInjection(t *testing.T) {
	code := `
require "elasticsearch"

def purge(params)
  tag = params[:tag]
  client = Elasticsearch::Client.new
  client.delete_by_query(index: "items", body: {
    query: { match: { tag: tag } }
  })
end
`
	flows := Analyze(code, "/app/controllers/purge_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected DSL injection flow for params -> Elasticsearch client.delete_by_query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_Elasticsearch_UpdateByQuery_PainlessRCE(t *testing.T) {
	code := `
require "elasticsearch"

def bulk_update(params)
  src = params[:script_source]
  client = Elasticsearch::Client.new
  client.update_by_query(index: "items", body: {
    script: { source: src, lang: "painless" },
    query: { match_all: {} },
  })
end
`
	flows := Analyze(code, "/app/controllers/update_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected Painless RCE flow for params -> Elasticsearch client.update_by_query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_Elasticsearch_ScriptsPainlessExecute_RCE(t *testing.T) {
	code := `
require "elasticsearch"

def run_script(params)
  src = params[:source]
  client = Elasticsearch::Client.new
  client.scripts_painless_execute(body: {
    script: { source: src, lang: "painless" }
  })
end
`
	flows := Analyze(code, "/app/controllers/script_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected direct Painless RCE flow for params -> Elasticsearch client.scripts_painless_execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_Elasticsearch_PutScript_StoredRCE(t *testing.T) {
	code := `
require "elasticsearch"

def save_script(params)
  src = params[:src]
  client = Elasticsearch::Client.new
  client.put_script(id: "calc", body: {
    script: { source: src, lang: "painless" }
  })
end
`
	flows := Analyze(code, "/app/controllers/script_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected stored-script RCE flow for params -> Elasticsearch client.put_script")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_Elasticsearch_Reindex_PainlessRCE(t *testing.T) {
	code := `
require "elasticsearch"

def remap(params)
  src = params[:script_source]
  client = Elasticsearch::Client.new
  client.reindex(body: {
    source: { index: "src" },
    dest:   { index: "dest" },
    script: { source: src, lang: "painless" },
  })
end
`
	flows := Analyze(code, "/app/controllers/reindex_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected Painless RCE flow for params -> Elasticsearch client.reindex")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_Elasticsearch_SearchTemplate_MustacheInjection(t *testing.T) {
	code := `
require "elasticsearch"

def render_search(params)
  tmpl = params[:template]
  client = Elasticsearch::Client.new
  client.search_template(index: "logs", body: {
    source: tmpl,
    params: { value: "x" },
  })
end
`
	flows := Analyze(code, "/app/controllers/template_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Mustache+DSL injection flow for params -> Elasticsearch client.search_template")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// OpenSearch is a fork of Elasticsearch with the same client surface.
// Verify our sinks fire on opensearch-ruby code paths too.
func TestRuby_OpenSearch_DeleteByQuery_DSLInjection(t *testing.T) {
	code := `
require "opensearch"

def purge(params)
  tag = params[:tag]
  os_client = OpenSearch::Client.new
  os_client.delete_by_query(index: "items", body: {
    query: { match: { tag: tag } }
  })
end
`
	flows := Analyze(code, "/app/controllers/opensearch_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected DSL injection flow for params -> OpenSearch client.delete_by_query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// --- Negative tests: safe usage must not trigger the new sinks ---

// Hardcoded Painless script source: still uses a Painless sink method but
// with a constant string literal, no taint reaches the body. The sink should
// not fire because the body has no taint flowing into it.
func TestRuby_Elasticsearch_Safe_HardcodedScriptSource(t *testing.T) {
	code := `
require "elasticsearch"

def bump
  client = Elasticsearch::Client.new
  client.update_by_query(index: "items", body: {
    script: { source: "ctx._source.count++", lang: "painless" },
    query: { match_all: {} },
  })
end
`
	flows := Analyze(code, "/app/controllers/safe_controller.rb", rules.LangRuby)
	for _, f := range flows {
		if f.Sink.ID == "ruby.elasticsearch.update_by_query" {
			t.Errorf("unexpected update_by_query sink firing on hardcoded script: source=%s", f.Source.Category)
		}
	}
}
