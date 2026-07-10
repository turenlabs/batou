package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Swift — tuple-destructuring declaration taint propagation (recall fix)
// =========================================================================
//
// tree-sitter-swift parses `let (a, b) = rhs` as a property_declaration whose
// `name` pattern is the tuple `(a, b)`; each element is wrapped in its own
// nested `pattern` node. extractVarDeclParts only pulls the first identifier,
// so before processSwiftDeconstruct every destructured local past the first
// silently lost its taint and a sink on it produced ZERO flows. The shapes
// below all flow user input (swift.vapor.req.query) through a tuple bind into
// SQLite.swift's Connection.execute (swift.sqliteswift.execute, SnkSQLQuery,
// receiver "db" matched against ObjectType "Connection").
//
// Function bodies deliberately avoid the isWebHandlerFunc auto-taint trigger
// substrings ("Query(", "Path(", bare "GET"/"POST", etc.) so the parameters
// are not auto-seeded and each assertion reflects the destructure binding only.

// --- Element-wise: tuple literal taints only the matching element ---------

func TestSwift_TupleDestructure_LiteralElementwise(t *testing.T) {
	code := `
import Vapor
import SQLite
func loadActor(req: Request, db: Connection) throws {
    let (actor, label) = (req.query, "audit")
    let sql = "SELECT * FROM events WHERE actor = '\(actor)' AND label = '\(label)'"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/LoadActor.swift", rules.LangSwift)
	if !hasFlowFromSource(flows, "swift.vapor.req.query", taint.SnkSQLQuery) {
		t.Error("expected SQLi flow for tuple-element bind (actor, _) = (req.query, _) -> db.execute")
		for _, f := range flows {
			t.Logf("  flow: %s(%s) -> %s(%s)", f.Source.Category, f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Element-wise precision: the constant element stays clean -------------

func TestSwift_TupleDestructure_SafeElementNoFlow(t *testing.T) {
	code := `
import Vapor
import SQLite
func loadConst(req: Request, db: Connection) throws {
    let (actor, label) = (req.query, "audit")
    let sql = "SELECT * FROM events WHERE label = '\(label)'"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/LoadConst.swift", rules.LangSwift)
	if hasFlowFromSource(flows, "swift.vapor.req.query", taint.SnkSQLQuery) {
		t.Error("did NOT expect a flow: the constant tuple element 'label' must stay untainted")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s(%s) -> %s(%s)", f.Source.Category, f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Wildcard element is skipped, the named one still binds ---------------

func TestSwift_TupleDestructure_WildcardElement(t *testing.T) {
	code := `
import Vapor
import SQLite
func loadFirst(req: Request, db: Connection) throws {
    let (actor, _) = (req.query, "ignored")
    let sql = "SELECT * FROM events WHERE actor = '\(actor)'"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/LoadFirst.swift", rules.LangSwift)
	if !hasFlowFromSource(flows, "swift.vapor.req.query", taint.SnkSQLQuery) {
		t.Error("expected SQLi flow for (actor, _) = (req.query, _) -> db.execute")
		for _, f := range flows {
			t.Logf("  flow: %s(%s) -> %s(%s)", f.Source.Category, f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Whole-RHS distribution: tuple-returning call on a tainted variable ----

func TestSwift_TupleDestructure_CallOnTaintedVar(t *testing.T) {
	code := `
import Vapor
import SQLite
func replay(req: Request, db: Connection) throws {
    let raw = req.query
    let (status, body) = decodePair(raw)
    let sql = "SELECT * FROM events WHERE body = '\(body)'"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/Replay.swift", rules.LangSwift)
	if !hasFlowFromSource(flows, "swift.vapor.req.query", taint.SnkSQLQuery) {
		t.Error("expected SQLi flow for (status, body) = decodePair(raw) -> db.execute")
		for _, f := range flows {
			t.Logf("  flow: %s(%s) -> %s(%s)", f.Source.Category, f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Whole-RHS distribution: direct tainted variable ----------------------

func TestSwift_TupleDestructure_DirectTaintedVar(t *testing.T) {
	code := `
import Vapor
import SQLite
func splitActor(req: Request, db: Connection) throws {
    let raw = req.query
    let (first, second) = raw
    let sql = "SELECT * FROM events WHERE actor = '\(second)'"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/SplitActor.swift", rules.LangSwift)
	if !hasFlowFromSource(flows, "swift.vapor.req.query", taint.SnkSQLQuery) {
		t.Error("expected SQLi flow for whole-RHS distribution (first, second) = raw -> db.execute")
		for _, f := range flows {
			t.Logf("  flow: %s(%s) -> %s(%s)", f.Source.Category, f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Pure negative: a constant-only tuple yields no flow ------------------

func TestSwift_TupleDestructure_ConstantNoFlow(t *testing.T) {
	code := `
import SQLite
func staticQuery(db: Connection) throws {
    let (a, b) = ("alice", "bob")
    let sql = "SELECT * FROM events WHERE actor = '\(a)' AND peer = '\(b)'"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/StaticQuery.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("did NOT expect any SQLi flow from a constant tuple; got %s(%s) -> %s(%s)",
				f.Source.Category, f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}
