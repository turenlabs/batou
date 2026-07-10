package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Ruby — MongoDB advanced NoSQL injection sinks (CWE-943 / CWE-94)
//
// Covers Mongo::Collection APIs that aren't represented by the existing
// find_one*/update_*/delete_* family in tsflow_ruby_mongo_test.go:
//   - ruby.mongo.collection.find          (CWE-943, SnkNoSQL)
//   - ruby.mongo.collection.distinct      (CWE-943, SnkNoSQL — filter at args[1])
//   - ruby.mongo.collection.watch         (CWE-943, SnkNoSQL — change stream pipeline)
//   - ruby.mongo.collection.map_reduce    (CWE-94,  SnkEval  — server-side JS)
//
// All four are tagged with the newer SnkNoSQL/SnkEval categories (the older
// Mongo entries above use SnkSQLQuery for legacy reasons; we don't migrate
// them here). ObjectType "Mongo::Collection" scopes to receivers that
// abbreviation-match `collection` (`coll`, `collec`, `collection`); class-
// name receivers like `User.find(...)` (ActiveRecord) won't trip the gate.
// =========================================================================

func TestRuby_Mongo_Find_NoSQLInjection(t *testing.T) {
	code := `
def search(params)
  q = params[:q]
  coll = Mongo::Client.new(["localhost:27017"]).use("app")[:users]
  rows = coll.find(name: q).to_a
end
`
	flows := Analyze(code, "/app/controllers/users_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected SnkNoSQL flow from params -> coll.find()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_Mongo_Find_AuthBypassOperator(t *testing.T) {
	// Real attack pattern: `name: params[:user], password: { "$ne" => "" }`
	// — but the simpler case (whole filter hash from params) is what we
	// verify here. tsflow taints the hash, the hash flows into find().
	code := `
def login(params)
  filter = params[:filter]
  coll = Mongo::Client.new(["localhost:27017"]).use("app")[:credentials]
  user = coll.find(filter).first
end
`
	flows := Analyze(code, "/app/controllers/sessions_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected SnkNoSQL flow for params filter -> coll.find() (auth bypass)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_Mongo_Distinct_FilterInjection(t *testing.T) {
	// Mongo::Collection#distinct(field, filter, opts) — the *second* arg is
	// the filter. DangerousArgs:[1] in the catalog entry; tsflow must reach
	// the second positional argument for the flow to register.
	code := `
def values(params)
  scope = params[:scope]
  coll = Mongo::Client.new(["localhost:27017"]).use("app")[:orders]
  vals = coll.distinct("status", scope)
end
`
	flows := Analyze(code, "/app/controllers/orders_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected SnkNoSQL flow from params -> coll.distinct() (filter at args[1])")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_Mongo_Watch_ChangeStreamPipelineInjection(t *testing.T) {
	// Change stream pipelines accept the same operators as aggregate; an
	// attacker-controlled pipeline can $lookup into other collections to
	// exfiltrate rows from an audit-log subscriber.
	code := `
def stream(params)
  pipeline = params[:pipeline]
  coll = Mongo::Client.new(["localhost:27017"]).use("app")[:audit]
  cs = coll.watch(pipeline)
end
`
	flows := Analyze(code, "/app/services/audit_stream.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected SnkNoSQL flow from params -> coll.watch() (change-stream pipeline injection)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_Mongo_MapReduce_MapJSInjection(t *testing.T) {
	// map_reduce arg 0 is JavaScript executed server-side. Tainted code
	// strings are full-blown CWE-94 (SnkEval), not just SnkNoSQL.
	code := `
def stats(params)
  map_fn = params[:map]
  coll = Mongo::Client.new(["localhost:27017"]).use("app")[:events]
  out = coll.map_reduce(map_fn, "function(k,v){return Array.sum(v);}")
end
`
	flows := Analyze(code, "/app/jobs/stats_job.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow from params -> coll.map_reduce() args[0] (server-side JS injection)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_Mongo_MapReduce_ReduceJSInjection(t *testing.T) {
	// arg 1 is the reduce function — also user-supplied JS.
	code := `
def stats(params)
  reduce_fn = params[:reduce]
  coll = Mongo::Client.new(["localhost:27017"]).use("app")[:events]
  out = coll.map_reduce("function(){emit(this.k,1);}", reduce_fn)
end
`
	flows := Analyze(code, "/app/jobs/stats_job.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow from params -> coll.map_reduce() args[1] (server-side JS injection)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// -------------------------------------------------------------------------
// Negative tests — must NOT fire
// -------------------------------------------------------------------------

// ActiveRecord's `User.find(params[:id])` is the most common Ruby ORM idiom;
// it must not match the new Mongo sink. Receiver "User" doesn't abbreviation-
// match "collection", so the matcher should reject it.
func TestRuby_Mongo_Find_ActiveRecordNoFalsePositive(t *testing.T) {
	code := `
def show(params)
  id = params[:id]
  user = User.find(id)
end
`
	flows := Analyze(code, "/app/controllers/users_controller.rb", rules.LangRuby)
	for _, f := range flows {
		if f.Sink.ID == "ruby.mongo.collection.find" {
			t.Errorf("ActiveRecord User.find(params[:id]) must NOT match ruby.mongo.collection.find — got: %s -> %s",
				f.Source.Category, f.Sink.Category)
		}
	}
}

// A fully-constant filter (no taint reaches the sink) must not produce a
// flow — guards against the "any call to .find(...) fires a finding" bug
// that the bare-name Mongo CRUD sinks exhibited (PR #638).
func TestRuby_Mongo_Find_ConstantFilterNoFlow(t *testing.T) {
	code := `
def healthy
  coll = Mongo::Client.new(["localhost:27017"]).use("app")[:health]
  coll.find(name: "active").to_a
end
`
	flows := Analyze(code, "/app/services/health_check.rb", rules.LangRuby)
	for _, f := range flows {
		if f.Sink.ID == "ruby.mongo.collection.find" {
			t.Errorf("constant filter must not produce a SnkNoSQL flow — got: %s -> %s",
				f.Source.Category, f.Sink.Category)
		}
	}
}
