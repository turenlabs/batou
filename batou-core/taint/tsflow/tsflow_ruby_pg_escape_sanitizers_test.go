package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Ruby — pg gem (ruby-pg) SQL-escaping return-value sanitizers (CWE-89)
//
// PG::Connection#escape_string / #escape_literal / #escape_identifier /
// #quote_ident wrap the libpq PQescape* family. They are the canonical way
// to safely interpolate a dynamic value or identifier (table / column name)
// into a SQL string when PQexec-style parameter binding ($1) cannot be used.
//
// Same model as the temporal sanitizers (cycle #757): the matcher sanitizes
// the LHS of `safe = conn.escape_*(tainted)`, not the original argument, so
// every fixture assigns the escaped result and flows THAT into the sink.
// Receiver `conn` matches ObjectType "PG::Connection" via the matcher's
// "connection"-keyword heuristic (matcher.go).
// =========================================================================

func TestRuby_Sanitizer_PGEscapeString_NeutralizesSQL(t *testing.T) {
	code := `
require "pg"

def search(params)
  name = params[:name]
  conn = PG.connect(dbname: "app")
  safe = conn.escape_string(name)
  conn.exec_params("SELECT * FROM users WHERE name = '" + safe + "'", [])
end
`
	flows := Analyze(code, "/app/controllers/users_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("PG#escape_string should neutralize SnkSQLQuery flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_Sanitizer_PGEscapeLiteral_NeutralizesSQL(t *testing.T) {
	code := `
require "pg"

def search(params)
  name = params[:name]
  conn = PG.connect(dbname: "app")
  lit = conn.escape_literal(name)
  conn.exec("SELECT * FROM users WHERE name = " + lit)
end
`
	flows := Analyze(code, "/app/controllers/users_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("PG#escape_literal should neutralize SnkSQLQuery flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_Sanitizer_PGEscapeIdentifier_NeutralizesSQL(t *testing.T) {
	code := `
require "pg"

def report(params)
  col = params[:col]
  conn = PG.connect(dbname: "app")
  ident = conn.escape_identifier(col)
  conn.exec("SELECT " + ident + " FROM reports")
end
`
	flows := Analyze(code, "/app/controllers/reports_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("PG#escape_identifier should neutralize SnkSQLQuery flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_Sanitizer_PGQuoteIdent_NeutralizesSQL(t *testing.T) {
	code := `
require "pg"

def report(params)
  tbl = params[:table]
  conn = PG.connect(dbname: "app")
  ident = conn.quote_ident(tbl)
  conn.async_exec("SELECT * FROM " + ident)
end
`
	flows := Analyze(code, "/app/controllers/reports_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("PG#quote_ident should neutralize SnkSQLQuery flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// -------------------------------------------------------------------------
// Negative control — without the escape call, the same shape MUST still fire
// (proves the test harness detects the flow and the sanitizer, not some
// unrelated reason, is what neutralizes it above).
// -------------------------------------------------------------------------

func TestRuby_Sanitizer_PGEscape_NegativeControl_StillFires(t *testing.T) {
	code := `
require "pg"

def search(params)
  name = params[:name]
  conn = PG.connect(dbname: "app")
  conn.exec_params("SELECT * FROM users WHERE name = '" + name + "'", [])
end
`
	flows := Analyze(code, "/app/controllers/users_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow when no PG escape sanitizer is applied")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}
