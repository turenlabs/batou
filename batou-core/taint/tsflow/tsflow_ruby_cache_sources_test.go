package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Ruby — ActiveSupport::Cache (Rails.cache) read sources (second-order taint).
//
// Rails.cache / ActiveSupport::Cache::Store is the dominant Rails caching API,
// backed by memcached, Redis, file, or memory stores. Values returned by
// read/fetch/read_multi/fetch_multi come from data previously written by the
// application or by external code — frequently under a user-controlled key —
// so they are classic second-order taint sources: a cached profile field
// replayed into SQL, a cached URL fetched server-side (SSRF), a cached command
// string handed to system().
//
// The existing Dalli entries (ruby.dalli.get / get_multi) only model the raw
// memcached client; these exercise the framework-level cache abstraction.
// =========================================================================

func TestRuby_CacheRead_CommandInjection(t *testing.T) {
	code := `
def run(cache)
  cmd = cache.read("pending:task")
  system(cmd)
end
`
	flows := Analyze(code, "/app/cache_read.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow from cache.read -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_CacheFetch_SSRF(t *testing.T) {
	code := `
require "net/http"

def proxy(cache)
  url = cache.fetch("upstream:endpoint")
  Net::HTTP.get(URI(url))
end
`
	flows := Analyze(code, "/app/cache_fetch.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow from cache.fetch -> Net::HTTP.get")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// Exercises the chained `Rails.cache.fetch(...)` receiver (no intermediate
// assignment) to confirm the dotted-receiver matcher path resolves it.
func TestRuby_RailsCacheFetch_DirectChain_CodeEval(t *testing.T) {
	code := `
def render
  snippet = Rails.cache.fetch("template:body")
  eval(snippet)
end
`
	flows := Analyze(code, "/app/rails_cache_fetch.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected code-eval flow from Rails.cache.fetch -> eval")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_CacheReadMulti_CommandInjection(t *testing.T) {
	code := `
def batch(cache)
  vals = cache.read_multi("a", "b")
  system("echo #{vals}")
end
`
	flows := Analyze(code, "/app/cache_read_multi.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow from cache.read_multi -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_CacheFetchMulti_SSRF(t *testing.T) {
	code := `
require "net/http"

def fan_out(cache)
  endpoints = cache.fetch_multi("svc:a", "svc:b") { {} }
  Net::HTTP.get(URI("http://#{endpoints}"))
end
`
	flows := Analyze(code, "/app/cache_fetch_multi.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow from cache.fetch_multi -> Net::HTTP.get")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// Negative control — a hardcoded literal flowing to the same sink must NOT be
// reported, proving the flow above comes from the cache source, not the sink.
func TestRuby_CacheRead_NoFlowOnConstant(t *testing.T) {
	code := `
def run(cache)
  cmd = "ls -la"
  system(cmd)
end
`
	flows := Analyze(code, "/app/cache_safe.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("did not expect a command-injection flow for a hardcoded constant")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s sink=%s", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// Catalog wiring assertion — fast feedback if an entry is dropped or renamed.
func TestRuby_CacheSources_Registered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangRuby)
	if cat == nil {
		t.Fatal("Ruby catalog not loaded")
	}
	have := map[string]taint.SourceCategory{}
	for _, s := range cat.Sources() {
		have[s.ID] = s.Category
	}
	expected := []string{
		"ruby.activesupport.cache.read",
		"ruby.activesupport.cache.fetch",
		"ruby.activesupport.cache.read_multi",
		"ruby.activesupport.cache.fetch_multi",
	}
	for _, id := range expected {
		c, ok := have[id]
		if !ok {
			t.Errorf("expected source %q to be registered", id)
			continue
		}
		if c != taint.SrcExternal {
			t.Errorf("source %q: expected category SrcExternal, got %v", id, c)
		}
	}
}
