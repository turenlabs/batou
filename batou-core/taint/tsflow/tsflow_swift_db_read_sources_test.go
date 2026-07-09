package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Swift — SQLite.swift / MongoSwift / MySQLNIO second-order DB-read sources
// =========================================================================
//
// Swift already models the *write* side of these drivers as injection sinks
// (swift.sqliteswift.{run,prepare,execute,scalar}, swift.mongoswift.
// collection.{findOne,aggregate,findOneAndUpdate,findOneAndDelete},
// swift.mysqlnio.simplequery). This file covers the new *read-back* sources:
// an attacker-controlled value persisted by one request and SELECTed back by
// a later one still carries its taint, and feeding it into a SQL sink without
// re-validation is second-order injection.
//
// Each test plumbs a DB-read result into SQLite.swift's Connection.execute
// (swift.sqliteswift.execute, DangerousArgs [0], ObjectType "Connection"
// matched against receiver "db" via the Connection heuristic in
// matcher.go). SQL-fetch keywords are kept out of the function bodies that
// matter (no "Query(", "Path(", bare "GET"/"POST"/"DELETE", etc.) so the
// isWebHandlerFunc auto-taint path in walker.go doesn't seed the typed
// parameters and mask whether the new source actually fires.

// --- SQLite.swift Connection.pluck -------------------------------------

func TestSwift_SQLiteSwift_Pluck_SecondOrder(t *testing.T) {
	code := `
import SQLite

func replayActor(db: Connection) throws {
    let row = try db.pluck(Table("users"))
    let actor = "\(row)"
    let sql = "SELECT * FROM audit WHERE actor = '\(actor)'"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/ReplayActor.swift", rules.LangSwift)
	if !hasFlowFromSource(flows, "swift.sqliteswift.pluck", taint.SnkSQLQuery) {
		t.Error("expected second-order SQLi flow for db.pluck -> db.execute")
		for _, f := range flows {
			t.Logf("  flow: %s(%s) -> %s(%s)", f.Source.Category, f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- SQLite.swift Connection.prepare -----------------------------------

func TestSwift_SQLiteSwift_Prepare_SecondOrder(t *testing.T) {
	code := `
import SQLite

func replayPrepared(db: Connection) throws {
    let stmt = try db.prepare("SELECT name FROM users")
    let name = "\(stmt)"
    let sql = "SELECT * FROM audit WHERE actor = '\(name)'"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/ReplayPrepared.swift", rules.LangSwift)
	if !hasFlowFromSource(flows, "swift.sqliteswift.prepare.result", taint.SnkSQLQuery) {
		t.Error("expected second-order SQLi flow for db.prepare -> db.execute")
		for _, f := range flows {
			t.Logf("  flow: %s(%s) -> %s(%s)", f.Source.Category, f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- SQLite.swift Connection.scalar ------------------------------------

func TestSwift_SQLiteSwift_Scalar_SecondOrder(t *testing.T) {
	code := `
import SQLite

func replayScalar(db: Connection) throws {
    let last = try db.scalar("SELECT MAX(note) FROM events")
    let v = "\(last)"
    let sql = "SELECT * FROM audit WHERE actor = '\(v)'"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/ReplayScalar.swift", rules.LangSwift)
	if !hasFlowFromSource(flows, "swift.sqliteswift.scalar.result", taint.SnkSQLQuery) {
		t.Error("expected second-order SQLi flow for db.scalar -> db.execute")
		for _, f := range flows {
			t.Logf("  flow: %s(%s) -> %s(%s)", f.Source.Category, f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- SQLite.swift Connection.prepareRowIterator ------------------------

func TestSwift_SQLiteSwift_PrepareRowIterator_SecondOrder(t *testing.T) {
	code := `
import SQLite

func replayIterator(db: Connection) throws {
    let iter = try db.prepareRowIterator("SELECT name FROM users")
    let name = "\(iter)"
    let sql = "SELECT * FROM audit WHERE actor = '\(name)'"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/ReplayIterator.swift", rules.LangSwift)
	if !hasFlowFromSource(flows, "swift.sqliteswift.preparerowiterator", taint.SnkSQLQuery) {
		t.Error("expected second-order SQLi flow for db.prepareRowIterator -> db.execute")
		for _, f := range flows {
			t.Logf("  flow: %s(%s) -> %s(%s)", f.Source.Category, f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- MongoSwift MongoCollection.findOne --------------------------------

func TestSwift_MongoSwift_FindOne_SecondOrder(t *testing.T) {
	code := `
import MongoSwift
import SQLite

func replayMongoDoc(collection: MongoCollection<BSONDocument>, db: Connection) async throws {
    let doc = try await collection.findOne(["role": "admin"])
    let actor = "\(doc)"
    let sql = "SELECT * FROM audit WHERE actor = '\(actor)'"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/ReplayMongoDoc.swift", rules.LangSwift)
	if !hasFlowFromSource(flows, "swift.mongoswift.collection.findone.result", taint.SnkSQLQuery) {
		t.Error("expected second-order SQLi flow for collection.findOne -> db.execute")
		for _, f := range flows {
			t.Logf("  flow: %s(%s) -> %s(%s)", f.Source.Category, f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- MongoSwift MongoCollection.aggregate ------------------------------

func TestSwift_MongoSwift_Aggregate_SecondOrder(t *testing.T) {
	code := `
import MongoSwift
import SQLite

func replayMongoAgg(collection: MongoCollection<BSONDocument>, db: Connection) async throws {
    let cursor = try await collection.aggregate([["$match": ["status": "open"]]])
    let s = "\(cursor)"
    let sql = "SELECT * FROM audit WHERE actor = '\(s)'"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/ReplayMongoAgg.swift", rules.LangSwift)
	if !hasFlowFromSource(flows, "swift.mongoswift.collection.aggregate.result", taint.SnkSQLQuery) {
		t.Error("expected second-order SQLi flow for collection.aggregate -> db.execute")
		for _, f := range flows {
			t.Logf("  flow: %s(%s) -> %s(%s)", f.Source.Category, f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- MongoSwift MongoCollection.distinct -------------------------------

func TestSwift_MongoSwift_Distinct_SecondOrder(t *testing.T) {
	code := `
import MongoSwift
import SQLite

func replayMongoDistinct(collection: MongoCollection<BSONDocument>, db: Connection) async throws {
    let values = try await collection.distinct(fieldName: "tag", filter: [:])
    let s = "\(values)"
    let sql = "SELECT * FROM audit WHERE tag = '\(s)'"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/ReplayMongoDistinct.swift", rules.LangSwift)
	if !hasFlowFromSource(flows, "swift.mongoswift.collection.distinct.result", taint.SnkSQLQuery) {
		t.Error("expected second-order SQLi flow for collection.distinct -> db.execute")
		for _, f := range flows {
			t.Logf("  flow: %s(%s) -> %s(%s)", f.Source.Category, f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- MongoSwift MongoCollection.findOneAndUpdate -----------------------

func TestSwift_MongoSwift_FindOneAndUpdate_SecondOrder(t *testing.T) {
	code := `
import MongoSwift
import SQLite

func replayMongoFOAU(collection: MongoCollection<BSONDocument>, db: Connection) async throws {
    let doc = try await collection.findOneAndUpdate(filter: ["id": 1], update: ["$set": ["seen": true]])
    let actor = "\(doc)"
    let sql = "SELECT * FROM audit WHERE actor = '\(actor)'"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/ReplayMongoFOAU.swift", rules.LangSwift)
	if !hasFlowFromSource(flows, "swift.mongoswift.collection.findoneandupdate.result", taint.SnkSQLQuery) {
		t.Error("expected second-order SQLi flow for collection.findOneAndUpdate -> db.execute")
		for _, f := range flows {
			t.Logf("  flow: %s(%s) -> %s(%s)", f.Source.Category, f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- MongoSwift MongoCollection.findOneAndDelete -----------------------

func TestSwift_MongoSwift_FindOneAndDelete_SecondOrder(t *testing.T) {
	code := `
import MongoSwift
import SQLite

func replayMongoFOAD(collection: MongoCollection<BSONDocument>, db: Connection) async throws {
    let doc = try await collection.findOneAndDelete(["id": 1])
    let actor = "\(doc)"
    let sql = "SELECT * FROM audit WHERE actor = '\(actor)'"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/ReplayMongoFOAD.swift", rules.LangSwift)
	if !hasFlowFromSource(flows, "swift.mongoswift.collection.findoneanddelete.result", taint.SnkSQLQuery) {
		t.Error("expected second-order SQLi flow for collection.findOneAndDelete -> db.execute")
		for _, f := range flows {
			t.Logf("  flow: %s(%s) -> %s(%s)", f.Source.Category, f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- MySQLNIO MySQLConnection.simpleQuery ------------------------------

func TestSwift_MySQLNIO_SimpleQuery_SecondOrder(t *testing.T) {
	code := `
import MySQLNIO
import SQLite

func replayMySQLRows(conn: MySQLConnection, db: Connection) throws {
    let rows = try conn.simpleQuery("SELECT name FROM users")
    let s = "\(rows)"
    let sql = "SELECT * FROM audit WHERE actor = '\(s)'"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/ReplayMySQLRows.swift", rules.LangSwift)
	if !hasFlowFromSource(flows, "swift.mysqlnio.simplequery.result", taint.SnkSQLQuery) {
		t.Error("expected second-order SQLi flow for conn.simpleQuery -> db.execute")
		for _, f := range flows {
			t.Logf("  flow: %s(%s) -> %s(%s)", f.Source.Category, f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Negative: unused DB reads + constant SQL → no flow ----------------
//
// Verifies the new read sources don't synthesize spurious SnkSQLQuery flows
// when their results are discarded and the SQL handed to execute is a literal.
// (MySQLNIO's `simpleQuery` is intentionally omitted here — the literal
// substring "Query(" trips isWebHandlerFunc and seeds every parameter, which
// is unrelated to whether the new sources fire; that path is exercised by the
// positive TestSwift_MySQLNIO_SimpleQuery_SecondOrder test instead.)

func TestSwift_DBRead_NoFlow_OnConstantSQL(t *testing.T) {
	code := `
import SQLite
import MongoSwift

func warmEverything(db: Connection, collection: MongoCollection<BSONDocument>) async throws {
    _ = try db.pluck(Table("users"))
    _ = try db.prepare("SELECT 1")
    _ = try db.scalar("SELECT 1")
    _ = try db.prepareRowIterator("SELECT 1")
    _ = try await collection.findOne(["x": 1])
    _ = try await collection.aggregate([["$match": ["x": 1]]])
    _ = try await collection.distinct(fieldName: "f", filter: [:])
    _ = try await collection.findOneAndUpdate(filter: ["x": 1], update: ["$set": ["y": 1]])
    _ = try await collection.findOneAndDelete(["x": 1])
    let sql = "SELECT 1"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/WarmEverything.swift", rules.LangSwift)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did NOT expect SnkSQLQuery flow for discarded DB reads + constant SQL")
		for _, f := range flows {
			t.Logf("  flow: %s(%s) -> %s(%s)", f.Source.Category, f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Registration sanity: new source IDs are present in the catalog ----

func TestSwift_DBReadSources_Registered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangSwift)
	want := map[string]bool{
		"swift.sqliteswift.pluck":                             false,
		"swift.sqliteswift.prepare.result":                    false,
		"swift.sqliteswift.scalar.result":                     false,
		"swift.sqliteswift.preparerowiterator":                false,
		"swift.mongoswift.collection.findone.result":          false,
		"swift.mongoswift.collection.aggregate.result":        false,
		"swift.mongoswift.collection.distinct.result":         false,
		"swift.mongoswift.collection.findoneandupdate.result": false,
		"swift.mongoswift.collection.findoneanddelete.result": false,
		"swift.mysqlnio.simplequery.result":                   false,
	}
	for _, s := range cat.Sources() {
		if _, ok := want[s.ID]; ok {
			want[s.ID] = true
			if s.Category != taint.SrcDatabase {
				t.Errorf("source %s: expected Category SrcDatabase, got %v", s.ID, s.Category)
			}
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("expected source %s to be registered in the Swift catalog", id)
		}
	}
}
