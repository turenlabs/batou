package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Swift — SQLite.swift (stephencelis) raw-SQL injection tests (CWE-89)
// =========================================================================
//
// SQLite.swift exposes `Connection.run / prepare / execute / scalar` that
// accept a raw SQL string as arg 0 and optional parameter bindings as arg 1+.
// Tainted data interpolated into the SQL string is SQL injection.
//
// Param name `input`/`query` triggers tsflow's isInputParamName seed path;
// the `db.method(...)` call is matched via the `Connection` receiver
// heuristic in matcher.go (covers receiver names: db/conn/connection).

// Connection.run(_ statement: String) with tainted SQL interpolation.
func TestSwift_SQLiteSwift_Run_TaintedSQL(t *testing.T) {
	code := `
import SQLite

func handler(input: String) throws {
    let db = try Connection("app.sqlite")
    try db.run("INSERT INTO users (email) VALUES ('\(input)')")
}
`
	flows := Analyze(code, "/app/UsersHandler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for input -> Connection.run()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Connection.prepare(_ statement: String) with tainted ORDER BY column.
func TestSwift_SQLiteSwift_Prepare_TaintedSQL(t *testing.T) {
	code := `
import SQLite

func handler(input: String) throws {
    let db = try Connection("app.sqlite")
    let stmt = try db.prepare("SELECT * FROM users ORDER BY \(input)")
    _ = stmt
}
`
	flows := Analyze(code, "/app/SortHandler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for input -> Connection.prepare()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Connection.execute(_ SQL: String) — multi-statement batch.
func TestSwift_SQLiteSwift_Execute_TaintedBatch(t *testing.T) {
	code := `
import SQLite

func handler(input: String) throws {
    let db = try Connection("app.sqlite")
    try db.execute("CREATE TABLE \(input) (id INTEGER PRIMARY KEY)")
}
`
	flows := Analyze(code, "/app/MigrateHandler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for input -> Connection.execute()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Connection.scalar(_ statement: String) — single-value SELECT.
func TestSwift_SQLiteSwift_Scalar_TaintedSQL(t *testing.T) {
	code := `
import SQLite

func handler(input: String) throws -> Int? {
    let db = try Connection("app.sqlite")
    let count = try db.scalar("SELECT COUNT(*) FROM users WHERE \(input)") as? Int
    return count
}
`
	flows := Analyze(code, "/app/CountHandler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for input -> Connection.scalar()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Safe: tainted value passed as a parameter binding (arg 1+), NOT interpolated
// into the SQL string. DangerousArgs: []int{0} means only arg 0 is dangerous
// — taint reaching a binding arg should not produce a flow for these sinks.
func TestSwift_SQLiteSwift_Run_ParameterizedBinding_Safe(t *testing.T) {
	code := `
import SQLite

func handler(input: String) throws {
    let db = try Connection("app.sqlite")
    try db.run("INSERT INTO users (email) VALUES (?)", input)
}
`
	flows := Analyze(code, "/app/SafeHandler.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Sink.ID == "swift.sqliteswift.run" {
			t.Errorf("expected NO SnkSQLQuery flow for swift.sqliteswift.run when user input is a parameter binding, got %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
