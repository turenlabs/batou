package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Swift — Vapor Fluent / SQLKit raw-SQL injection tests (CWE-89)
// =========================================================================
//
// Vapor's ORM (Fluent) and its SQL layer (SQLKit) expose `.raw(_:)` as the
// raw-SQL escape hatch — the canonical server-side SQL-injection vector in
// Swift web code:
//
//     try await req.db.raw("SELECT * FROM users WHERE id = \(userId)")
//     try await db.raw(SQLQueryString("SELECT … '\(name)'")).all()
//
// This is the IDENTICAL pattern Batou catches at dataflow tier (CWE-89,
// conf 1.0) in Java (`stmt.executeQuery("… " + userId)`), Python
// (`cursor.execute("… " + user_id)`), and even Swift's own GRDB raw fetch —
// a language-parity gap (the catalog sinks were dead: keyed under a
// dotted/parenthetical MethodName `db.raw()` / `raw(SQLQueryString)` that
// tsflow's bare-name keying mangled into an unreachable map key, plus an
// `ObjectType:"Fluent"` framework name no real receiver carries).
//
// The SQLKit-recommended SAFE form binds the value as a query parameter via
// the `\(bind: x)` interpolation label, which must NOT fire.

// req.db.raw with a tainted raw string interpolation — the injection form.
func TestSwift_Fluent_RawSQL_TaintedInterpolation(t *testing.T) {
	code := `
import Vapor
import SQLKit

func handler(req: Request) async throws -> String {
    let userId = req.query["id"]
    let rows = try await req.db.raw("SELECT * FROM users WHERE id = \(userId)").all()
    _ = rows
    return "ok"
}
`
	flows := Analyze(code, "/app/UserController.swift", rules.LangSwift)
	if !hasFlowFromSink(flows, "swift.fluent.raw", taint.SnkSQLQuery) &&
		!hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("expected CWE-89 SQL flow for req.query -> req.db.raw(\\(userId)); got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sinkID=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// db.raw(SQLQueryString(...)) with a tainted interpolation — the explicit
// SQLQueryString construction form.
func TestSwift_Fluent_RawSQL_SQLQueryString_Tainted(t *testing.T) {
	code := `
import SQLKit

func handler(req: Request) async throws -> String {
    let name = req.parameters.get("name") ?? ""
    let rows = try await db.raw(SQLQueryString("SELECT * FROM accounts WHERE name = '\(name)'")).all()
    _ = rows
    return "ok"
}
`
	flows := Analyze(code, "/app/AccountRepo.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("expected CWE-89 SQL flow for req.parameters -> db.raw(SQLQueryString); got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sinkID=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// SAFE: parameterized `\(bind: userId)` binding — the SQLKit-recommended form
// that emits a placeholder and passes the value out-of-band. Must NOT fire.
func TestSwift_Fluent_RawSQL_Bind_Safe(t *testing.T) {
	code := `
import SQLKit

func handler(req: Request) async throws -> String {
    let userId = req.query["id"]
    let rows = try await req.db.raw("SELECT * FROM users WHERE id = \(bind: userId)").all()
    _ = rows
    return "ok"
}
`
	flows := Analyze(code, "/app/SafeRepo.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("expected NO SQL flow for parameterized \\(bind:) query, got %s -> %s (sinkID=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// SAFE: constant SQL string with no interpolated user input. Must NOT fire.
func TestSwift_Fluent_RawSQL_Constant_Safe(t *testing.T) {
	code := `
import SQLKit

func handler(req: Request) async throws -> String {
    let rows = try await req.db.raw("SELECT * FROM users WHERE active = 1").all()
    _ = rows
    return "ok"
}
`
	flows := Analyze(code, "/app/ConstRepo.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("expected NO SQL flow for constant query, got %s -> %s (sinkID=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// NEGATIVE: a benign non-SQL `.raw(` call whose argument is not a string
// literal (e.g. a byte-buffer constructor) must NOT match the SQL sink — the
// `\.raw\(\s*"` pattern requires a string-literal first argument.
func TestSwift_Fluent_RawSQL_NonStringRaw_NoFire(t *testing.T) {
	code := `
import Foundation

func handler(req: Request) throws {
    let name = req.query["name"]
    let buffer = ByteBuffer.raw(name)
    _ = buffer
}
`
	flows := Analyze(code, "/app/Buffer.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("expected NO SQL flow for non-string ByteBuffer.raw(name), got %s -> %s (sinkID=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}
