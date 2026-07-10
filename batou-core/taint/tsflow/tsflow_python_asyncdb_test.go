package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Python async DB driver SQL injection sinks (CWE-89)
// Covers: asyncpg, aiosqlite, encode/databases
// =========================================================================

func TestPython_AsyncDB_SinksRegistered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangPython)
	if cat == nil {
		t.Fatal("Python catalog not loaded")
	}
	sinks := cat.Sinks()
	found := map[string]bool{}
	for _, s := range sinks {
		if s.Category == taint.SnkSQLQuery {
			found[s.ID] = true
		}
	}
	want := []string{
		"py.asyncpg.execute",
		"py.asyncpg.fetchquery",
		"py.asyncpg.cursor",
		"py.aiosqlite.execute",
		"py.aiosqlite.executescript",
		"py.databases.execute",
		"py.databases.fetch",
	}
	for _, id := range want {
		if !found[id] {
			t.Errorf("missing expected SnkSQLQuery sink: %s", id)
		}
	}
}

// --- asyncpg ---

func TestPython_Asyncpg_Execute_SQLi(t *testing.T) {
	code := `
from flask import request

async def handler():
    name = request.args.get("name")
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    await conn.execute(query)
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from request.args -> conn.execute()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_Asyncpg_Fetchrow_SQLi(t *testing.T) {
	code := `
from fastapi import Request

async def get_user(request: Request):
    uid = request.query_params.get("id")
    q = f"SELECT * FROM users WHERE id = {uid}"
    row = await conn.fetchrow(q)
    return row
`
	flows := Analyze(code, "/app/routes.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from request.query_params -> conn.fetchrow()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_Asyncpg_Fetchval_Pool_SQLi(t *testing.T) {
	code := `
from flask import request

async def count():
    status = request.args.get("status")
    q = "SELECT COUNT(*) FROM orders WHERE status = '" + status + "'"
    n = await pool.fetchval(q)
    return n
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from request.args -> pool.fetchval()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_Asyncpg_SafeParameterized_NoFlow(t *testing.T) {
	code := `
from flask import request

async def handler():
    name = request.args.get("name")
    # Safe: parameterized query with $1 placeholder — name is bound, not interpolated.
    row = await conn.fetchrow("SELECT * FROM users WHERE name = $1", name)
    return row
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Sink.ID == "py.asyncpg.fetchquery" {
			t.Errorf("unexpected SQL injection flow on parameterized asyncpg query (arg 1 is bound): %+v", f)
		}
	}
}

// --- aiosqlite ---

func TestPython_Aiosqlite_Execute_SQLi(t *testing.T) {
	code := `
from flask import request
import aiosqlite

async def search():
    term = request.args.get("q")
    query = "SELECT * FROM items WHERE name LIKE '%" + term + "%'"
    async with aiosqlite.connect("app.db") as db:
        await db.execute(query)
`
	flows := Analyze(code, "/app/search.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from request.args -> aiosqlite db.execute()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_Aiosqlite_ExecuteScript_SQLi(t *testing.T) {
	code := `
from flask import request

async def run_migration():
    user_sql = request.form.get("sql")
    async with aiosqlite.connect("db.sqlite") as db:
        await db.executescript(user_sql)
`
	flows := Analyze(code, "/app/admin.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from request.form -> aiosqlite db.executescript()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- encode/databases ---

func TestPython_Databases_Execute_SQLi(t *testing.T) {
	code := `
from flask import request
from databases import Database

database = Database("postgresql://localhost")

async def register():
    email = request.form.get("email")
    query = "INSERT INTO users (email) VALUES ('" + email + "')"
    await database.execute(query)
`
	flows := Analyze(code, "/app/register.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from request.form -> databases.Database.execute()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_Databases_FetchAll_SQLi(t *testing.T) {
	code := `
from flask import request

async def list_orders():
    uid = request.args.get("uid")
    q = f"SELECT * FROM orders WHERE user_id = {uid}"
    rows = await database.fetch_all(q)
    return rows
`
	flows := Analyze(code, "/app/orders.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from request.args -> databases.Database.fetch_all()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_Databases_SafeNamedBind_NoFlow(t *testing.T) {
	code := `
from flask import request

async def safe_lookup():
    uid = request.args.get("uid")
    # Safe: named-bind with :uid — driver parameterizes the value.
    row = await database.fetch_one("SELECT * FROM orders WHERE user_id = :uid", values={"uid": uid})
    return row
`
	flows := Analyze(code, "/app/orders.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Sink.ID == "py.databases.fetch" {
			t.Errorf("unexpected SQL injection flow on parameterized databases query (values kwarg is bound): %+v", f)
		}
	}
}
