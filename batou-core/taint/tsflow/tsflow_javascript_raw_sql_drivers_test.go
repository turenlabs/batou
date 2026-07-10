package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// ===========================================================================
// JavaScript/TypeScript — raw SQL-driver injection sinks
//
// The generic js.sql.query / js.sql.execute / js.sql.prepare catch-alls
// (ObjectType "") already cover .query()/.execute()/.prepare() on any receiver,
// so node-postgres (pg) and mysql2 raw queries are caught. These tests cover
// the raw-driver methods that those catch-alls miss:
//
//   sql.unsafe(query)   postgres.js (porsager)   CWE-89  js.postgres.unsafe
//   db.run(sql)         node-sqlite3 / bun:sqlite CWE-89  js.sqlite.run
//   db.each(sql, cb)    node-sqlite3             CWE-89  js.sqlite.each
//
// db.exec(sql) is intentionally NOT a new entry — it is already detected by
// js.cloudflare.d1.exec (ObjectType "D1Database" contains the substring
// "database", which the matcher's heuristic maps onto the `db` receiver).
// ===========================================================================

// hasSinkID reports whether any flow terminates at the given sink ID.
func hasSinkID(flows []taint.TaintFlow, sinkID string) bool {
	for _, f := range flows {
		if f.Sink.ID == sinkID {
			return true
		}
	}
	return false
}

// --- postgres.js sql.unsafe() ---

func TestJS_Postgres_Unsafe_SQLInjection(t *testing.T) {
	code := `
async function handler(request) {
    const name = request.query.name;
    await sql.unsafe("SELECT * FROM users WHERE name = '" + name + "'");
}
`
	flows := Analyze(code, "/app/db/pg.js", rules.LangJavaScript)
	if !hasSinkID(flows, "js.postgres.unsafe") {
		t.Error("expected js.postgres.unsafe SQL flow: request.query -> sql.unsafe")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%s)", f.Source.ID, f.Sink.ID, f.Sink.Category)
		}
	}
}

func TestJS_Postgres_Unsafe_TemplateLiteral(t *testing.T) {
	code := `
async function handler(request) {
    const id = request.query.id;
    await sql.unsafe(` + "`SELECT * FROM orders WHERE user_id = '${id}'`" + `);
}
`
	flows := Analyze(code, "/app/db/pgtpl.js", rules.LangJavaScript)
	if !hasSinkID(flows, "js.postgres.unsafe") {
		t.Error("expected js.postgres.unsafe via template literal: request.query -> sql.unsafe")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// --- node-sqlite3 / bun:sqlite db.run() ---

func TestJS_Sqlite_Run_SQLInjection(t *testing.T) {
	code := `
function handler(request) {
    const name = request.query.name;
    db.run("INSERT INTO users (name) VALUES ('" + name + "')");
}
`
	flows := Analyze(code, "/app/db/sqlite.js", rules.LangJavaScript)
	if !hasSinkID(flows, "js.sqlite.run") {
		t.Error("expected js.sqlite.run SQL flow: request.query -> db.run")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%s)", f.Source.ID, f.Sink.ID, f.Sink.Category)
		}
	}
}

// --- node-sqlite3 db.each() ---

func TestJS_Sqlite_Each_SQLInjection(t *testing.T) {
	code := `
function handler(request) {
    const name = request.query.name;
    db.each("SELECT * FROM users WHERE name = '" + name + "'", (err, row) => {});
}
`
	flows := Analyze(code, "/app/db/sqliteeach.js", rules.LangJavaScript)
	if !hasSinkID(flows, "js.sqlite.each") {
		t.Error("expected js.sqlite.each SQL flow: request.query -> db.each")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%s)", f.Source.ID, f.Sink.ID, f.Sink.Category)
		}
	}
}

// --- Negative controls: constant SQL must not flow ---

func TestJS_RawSqlDrivers_ConstantSQL_NoFlow(t *testing.T) {
	code := `
async function migrate() {
    await sql.unsafe("CREATE TABLE IF NOT EXISTS audit (id SERIAL PRIMARY KEY)");
    db.run("CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY)");
    db.each("SELECT 1", (err, row) => {});
}
`
	flows := Analyze(code, "/app/db/migrate.js", rules.LangJavaScript)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("constant SQL must NOT trigger a SnkSQLQuery flow")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}
