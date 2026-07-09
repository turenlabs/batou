package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// ===========================================================================
// JavaScript/TypeScript — raw-SQL escape hatches in modern Node SQL drivers.
//
// The catalog already models the raw-SQL escape hatches of the previous
// generation of drivers (Prisma $queryRawUnsafe/$executeRawUnsafe, Drizzle
// sql.raw / db.execute, TypeORM .query). Two heavily-adopted 2024/2025-era
// drivers were missing their escape hatch:
//
//   * postgres.js (porsager/postgres): the tagged-template form
//     sql`...${value}...` binds values as $N parameters and is safe, but
//     sql.unsafe(query) runs an unparameterized string verbatim — a tainted
//     query is SQL injection.
//
//   * node:sqlite (Node 22+ DatabaseSync) and better-sqlite3: db.exec(sql)
//     runs one or more raw statements with no parameterization (stacked
//     statements allowed) — a tainted statement is SQL injection.
//
// Both sinks are scoped by ObjectType ("sql" / "DatabaseSync"); the latter
// also matches the conventional db/database/sqlite receivers via the
// database-name heuristic in matchesCatalogEntry.
// ===========================================================================

// --- Catalog verification ---

func TestJS_NodeSQLEscape_SinksRegistered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangJavaScript)
	if cat == nil {
		t.Fatal("JavaScript catalog not loaded")
	}
	found := map[string]bool{}
	for _, s := range cat.Sinks() {
		found[s.ID] = true
	}
	for _, id := range []string{"js.postgres.unsafe", "js.node_sqlite.exec"} {
		if !found[id] {
			t.Errorf("missing expected SQL sink: %s", id)
		}
	}
}

// hasSinkID is defined in tsflow_javascript_raw_sql_drivers_test.go (same
// package) — both JS SQL-sink suites share the one helper.

// --- postgres.js sql.unsafe() — SQL injection ---

func TestJS_PostgresJS_Unsafe_SQLi(t *testing.T) {
	code := `
function search(req, res) {
    const name = req.query.name;
    const rows = sql.unsafe("SELECT * FROM users WHERE name = '" + name + "'");
    res.json(rows);
}
`
	flows := Analyze(code, "/app/routes/search.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) || !hasSinkID(flows, "js.postgres.unsafe") {
		t.Error("expected SQL injection flow from req.query.name -> sql.unsafe()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// --- node:sqlite DatabaseSync.exec() — SQL injection (receiver `db`) ---

func TestJS_NodeSQLite_Exec_SQLi(t *testing.T) {
	code := `
function dropTable(req) {
    const tbl = req.body.table;
    db.exec("DROP TABLE " + tbl);
}
`
	flows := Analyze(code, "/app/admin/migrate.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) || !hasSinkID(flows, "js.node_sqlite.exec") {
		t.Error("expected SQL injection flow from req.body.table -> db.exec()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// --- better-sqlite3 db.exec() — same sink, `database` receiver heuristic ---

func TestJS_BetterSQLite3_Exec_SQLi(t *testing.T) {
	code := `
function runRaw(req) {
    const stmt = req.params.stmt;
    database.exec("PRAGMA " + stmt);
}
`
	flows := Analyze(code, "/app/db/raw.js", rules.LangJavaScript)
	if !hasSinkID(flows, "js.node_sqlite.exec") {
		t.Error("expected SQL injection flow from req.params.stmt -> database.exec()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// --- Negative regression: constant SQL, no taint -> no SQL flow ---

func TestJS_NodeSQLEscape_Negative_ConstantSQL(t *testing.T) {
	code := `
function init() {
    db.exec("CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY)");
    sql.unsafe("SELECT 1");
}
`
	flows := Analyze(code, "/app/db/init.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.ID == "js.node_sqlite.exec" || f.Sink.ID == "js.postgres.unsafe" {
			t.Errorf("constant SQL should not produce a flow, got: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}
