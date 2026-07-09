package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Ruby — PG gem SQL injection sinks
// =========================================================================

func TestRuby_PG_ExecParams_SQLInjection(t *testing.T) {
	code := `
require "pg"

def search(params)
  name = params[:name]
  conn = PG.connect(dbname: "app")
  conn.exec_params("SELECT * FROM users WHERE name = '" + name + "'", [])
end
`
	flows := Analyze(code, "/app/search.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from params -> PG#exec_params")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_PG_AsyncExec_SQLInjection(t *testing.T) {
	code := `
require "pg"

def orders(params)
  oid = params[:order_id]
  conn = PG.connect(dbname: "app")
  conn.async_exec("SELECT * FROM orders WHERE id = #{oid}")
end
`
	flows := Analyze(code, "/app/orders.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from params -> PG#async_exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_PG_SyncExec_SQLInjection(t *testing.T) {
	code := `
require "pg"

def tags(params)
  tag = params[:tag]
  conn = PG.connect(dbname: "app")
  conn.sync_exec("SELECT * FROM tags WHERE label = '#{tag}'")
end
`
	flows := Analyze(code, "/app/tags.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from params -> PG#sync_exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_PG_SendQuery_SQLInjection(t *testing.T) {
	code := `
require "pg"

def bulk(params)
  filter = params[:filter]
  conn = PG.connect(dbname: "app")
  conn.send_query("SELECT * FROM items WHERE type = '#{filter}'")
end
`
	flows := Analyze(code, "/app/bulk.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from params -> PG#send_query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_PG_Prepare_SQLInjection(t *testing.T) {
	code := `
require "pg"

def lookup(params)
  col = params[:col]
  conn = PG.connect(dbname: "app")
  conn.prepare("stmt1", "SELECT #{col} FROM users WHERE id = $1")
end
`
	flows := Analyze(code, "/app/lookup.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from params -> PG#prepare (second arg)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// =========================================================================
// Ruby — Mysql2 gem SQL injection sinks
// =========================================================================

func TestRuby_Mysql2_Query_SQLInjection(t *testing.T) {
	code := `
require "mysql2"

def users(params)
  name = params[:name]
  client = Mysql2::Client.new(host: "localhost", database: "app")
  client.query("SELECT * FROM users WHERE name = '#{name}'")
end
`
	flows := Analyze(code, "/app/users.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from params -> Mysql2::Client#query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_Mysql2_Prepare_SQLInjection(t *testing.T) {
	code := `
require "mysql2"

def reports(params)
  col = params[:col]
  client = Mysql2::Client.new(host: "localhost", database: "app")
  client.prepare("SELECT #{col} FROM reports WHERE id = ?")
end
`
	flows := Analyze(code, "/app/reports.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from params -> Mysql2::Client#prepare")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}
