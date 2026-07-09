package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Lua — lsqlite3 (LuaSQLite3) SQL injection (CWE-89)
//
// lsqlite3 is the canonical SQLite3 binding for Lua. The Database object
// returned by sqlite3.open / sqlite3.open_memory exposes raw-SQL methods
// (exec, nrows, rows, urows, first_row, prepare) that are SQL-injection
// sinks when user input is concatenated into the SQL string. Safe form
// uses ? placeholders + stmt:bind_values.
// =========================================================================

func TestLua_Lsqlite3_Exec_TaintedSQL(t *testing.T) {
	code := `
function handler()
    local user_id = ngx.req.get_uri_args()["id"]
    local sql = "DELETE FROM users WHERE id = " .. user_id
    db:exec(sql)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for ngx.req.get_uri_args -> db:exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_Lsqlite3_Nrows_TaintedSQL(t *testing.T) {
	code := `
function handler()
    local name = ngx.req.get_post_args()["name"]
    local query = "SELECT * FROM users WHERE name = '" .. name .. "'"
    for row in db:nrows(query) do
        ngx.say(row.id)
    end
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for ngx.req.get_post_args -> db:nrows")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_Lsqlite3_Urows_TaintedSQL(t *testing.T) {
	code := `
function handler()
    local q = ngx.req.get_uri_args()["q"]
    local sql = "SELECT id FROM logs WHERE message LIKE '%" .. q .. "%'"
    for id in database:urows(sql) do
        print(id)
    end
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for ngx.req.get_uri_args -> database:urows")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_Lsqlite3_FirstRow_TaintedSQL(t *testing.T) {
	code := `
function handler()
    local email = ngx.req.get_uri_args()["email"]
    local sql = "SELECT * FROM users WHERE email = '" .. email .. "'"
    local row = sqlite:first_row(sql)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for ngx.req.get_uri_args -> sqlite:first_row")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_Lsqlite3_Prepare_TaintedSQL(t *testing.T) {
	code := `
function handler()
    local user_id = ngx.req.get_uri_args()["id"]
    local sql = string.format("SELECT * FROM users WHERE id = %s", user_id)
    local stmt = db:prepare(sql)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for ngx.req.get_uri_args -> db:prepare with concatenated SQL")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Safe: SQL string is constant; user input is bound via stmt:bind_values
// after preparing. No taint reaches db:prepare's SQL argument.
func TestLua_Lsqlite3_Prepare_Parameterized_Safe(t *testing.T) {
	code := `
function handler()
    local user_id = ngx.req.get_uri_args()["id"]
    local stmt = db:prepare("SELECT * FROM users WHERE id = ?")
    stmt:bind_values(user_id)
    for row in stmt:nrows() do
        ngx.say(row.name)
    end
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Sink.ID == "lua.lsqlite3.prepare" {
			t.Errorf("expected no SQL injection flow for parameterized db:prepare, got: %s -> %s",
				f.Source.Category, f.Sink.Category)
		}
	}
}
