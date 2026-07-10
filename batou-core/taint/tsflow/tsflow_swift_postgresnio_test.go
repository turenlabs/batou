package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Swift — PostgresNIO raw-SQL injection tests (CWE-89)
// =========================================================================
//
// PostgresNIO is Vapor's official Postgres driver. The modern API uses
// `PostgresQuery` with ExpressibleByStringInterpolation so
// `\(value)` interpolation is a bound parameter (safe). Two escape hatches
// bypass that safety:
//
//   1. `PostgresQuery(unsafeSQL:)` — explicit raw-SQL constructor.
//   2. `connection.query("…", [PostgresData…])` legacy 2-arg form and
//      `connection.simpleQuery("…")` — arg 0 is a raw SQL string.
//
// Receiver names `conn`, `connection`, `db`, `postgres` are matched via the
// "Connection" receiver heuristic in tsflow/matcher.go.

// PostgresQuery(unsafeSQL:) with tainted SQL — explicit raw-SQL constructor.
func TestSwift_PostgresNIO_PostgresQuery_UnsafeSQL_Tainted(t *testing.T) {
	code := `
import PostgresNIO
import Vapor

func handler(req: Request) async throws {
    let name = req.query["name"] ?? ""
    let query = PostgresQuery(unsafeSQL: "SELECT * FROM users WHERE name = '\(name)'")
    _ = try await req.postgres.query(query)
}
`
	flows := Analyze(code, "/app/UsersHandler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for req.query -> PostgresQuery(unsafeSQL:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// PostgresConnection.query(_:,_:) legacy raw-SQL + bindings — arg 0 tainted.
func TestSwift_PostgresNIO_Query_TaintedSQLArg(t *testing.T) {
	code := `
import PostgresNIO

func handler(input: String) async throws {
    let connection = try await PostgresConnection.connect(configuration: .init(), id: 0, logger: .init(label: "pg"))
    _ = try await connection.query("SELECT * FROM users WHERE name = '\(input)'", [])
}
`
	flows := Analyze(code, "/app/UsersHandler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for input -> connection.query(rawSQL, [])")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// PostgresConnection.simpleQuery(_:) — single-statement raw-SQL execution.
func TestSwift_PostgresNIO_SimpleQuery_Tainted(t *testing.T) {
	code := `
import PostgresNIO

func handler(input: String) async throws {
    let connection = try await PostgresConnection.connect(configuration: .init(), id: 0, logger: .init(label: "pg"))
    _ = try await connection.simpleQuery("CREATE TABLE \(input) (id INT)")
}
`
	flows := Analyze(code, "/app/MigrateHandler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for input -> PostgresConnection.simpleQuery()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Safe: tainted value passed as a parameter binding (arg 1+), not interpolated
// into the SQL string. DangerousArgs: []int{0} means only arg 0 flags a flow
// for swift.postgresnio.query — a binding arg should not fire this sink.
func TestSwift_PostgresNIO_Query_ParameterizedBinding_Safe(t *testing.T) {
	code := `
import PostgresNIO
import Vapor

func handler(req: Request) async throws {
    let name = req.query["name"] ?? ""
    let conn = try await req.postgres.getConnection()
    _ = try await conn.query("SELECT * FROM users WHERE name = $1", [PostgresData(string: name)])
}
`
	flows := Analyze(code, "/app/SafeHandler.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Sink.ID == "swift.postgresnio.query" {
			t.Errorf("expected NO swift.postgresnio.query flow when tainted value only reaches PostgresData binding, got %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
