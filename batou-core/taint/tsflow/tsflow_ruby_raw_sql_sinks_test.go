package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Ruby — SQLite3::Database raw-SQL injection sinks (sqlite3-ruby gem)
//
// The sqlite3 gem's result-row READ methods (get_first_row / get_first_value)
// are already modeled as SrcDatabase sources; these tests cover the matching
// execution SINKS. Tests use the `database` receiver name (a strong match for
// ObjectType "SQLite3::Database") so attribution is unambiguous — `db` is only
// a weak heuristic match and the pg.prepare "connection" heuristic also accepts
// `db`, which would muddy the prepare assertion.
// =========================================================================

func TestRuby_SQLite3_Execute2_SQLInjection(t *testing.T) {
	code := `
require "sqlite3"

def search(params)
  name = params[:name]
  database = SQLite3::Database.new("app.db")
  database.execute2("SELECT * FROM users WHERE name = '#{name}'")
end
`
	flows := Analyze(code, "/app/search.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) || !findSinkID(flows, "ruby.sqlite3.execute2") {
		t.Error("expected SQL injection flow from params -> SQLite3::Database#execute2")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_SQLite3_ExecuteBatch_SQLInjection(t *testing.T) {
	code := `
require "sqlite3"

def seed(params)
	payload = params[:payload]
	database = SQLite3::Database.new("app.db")
	database.execute_batch("INSERT INTO logs VALUES ('#{payload}')")
end
`
	flows := Analyze(code, "/app/seed.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) || !findSinkID(flows, "ruby.sqlite3.execute_batch") {
		t.Error("expected SQL injection flow from params -> SQLite3::Database#execute_batch")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_SQLite3_ExecuteBatch2_SQLInjection(t *testing.T) {
	code := `
require "sqlite3"

def migrate(params)
  stmt = params[:stmt]
  database = SQLite3::Database.new("app.db")
  database.execute_batch2("SELECT * FROM t WHERE c = '#{stmt}'")
end
`
	flows := Analyze(code, "/app/migrate.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) || !findSinkID(flows, "ruby.sqlite3.execute_batch2") {
		t.Error("expected SQL injection flow from params -> SQLite3::Database#execute_batch2")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_SQLite3_Query_SQLInjection(t *testing.T) {
	code := `
require "sqlite3"

def listing(params)
  category = params[:category]
  database = SQLite3::Database.new("app.db")
  database.query("SELECT * FROM products WHERE category = '#{category}'")
end
`
	flows := Analyze(code, "/app/listing.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) || !findSinkID(flows, "ruby.sqlite3.query") {
		t.Error("expected SQL injection flow from params -> SQLite3::Database#query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_SQLite3_Prepare_SQLInjection(t *testing.T) {
	code := `
require "sqlite3"

def lookup(params)
  col = params[:col]
  database = SQLite3::Database.new("app.db")
  database.prepare("SELECT #{col} FROM users WHERE id = ?")
end
`
	flows := Analyze(code, "/app/lookup.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) || !findSinkID(flows, "ruby.sqlite3.prepare") {
		t.Error("expected SQL injection flow from params -> SQLite3::Database#prepare")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// =========================================================================
// Ruby — TinyTds::Client raw-SQL injection sink (FreeTDS / SQL Server)
// =========================================================================

func TestRuby_TinyTds_Execute_SQLInjection(t *testing.T) {
	code := `
require "tiny_tds"

def report(params)
  uid = params[:uid]
  client = TinyTds::Client.new(username: "sa", host: "db")
  client.execute("SELECT * FROM accounts WHERE uid = '#{uid}'")
end
`
	flows := Analyze(code, "/app/report.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) || !findSinkID(flows, "ruby.tiny_tds.execute") {
		t.Error("expected SQL injection flow from params -> TinyTds::Client#execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// =========================================================================
// Negative controls
// =========================================================================

// TinyTds::Client#escape neutralizes the interpolated value -> no flow.
func TestRuby_TinyTds_Escape_Sanitized_NoFlow(t *testing.T) {
	code := `
require "tiny_tds"

def report(params)
  uid = params[:uid]
  client = TinyTds::Client.new(username: "sa", host: "db")
  clean = client.escape(uid)
  client.execute("SELECT * FROM accounts WHERE uid = '#{clean}'")
end
`
	flows := Analyze(code, "/app/report_safe.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NO SQL injection flow after TinyTds::Client#escape sanitization")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// Constant SQL with no user input -> no flow.
func TestRuby_SQLite3_ConstantQuery_NoFlow(t *testing.T) {
	code := `
require "sqlite3"

def all_products
  database = SQLite3::Database.new("app.db")
  database.query("SELECT * FROM products")
end
`
	flows := Analyze(code, "/app/all_products.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NO SQL injection flow for a constant query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}
