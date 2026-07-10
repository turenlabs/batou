// batou:ignore-start all -- intentional vulnerable patterns embedded in inline Python strings for taint-flow unit tests
package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Python ClickHouse SQL injection sinks (CWE-89)
//
// Covers two dominant Python clients:
//   - clickhouse-connect (official): Client.query_df/query_np/query_arrow/
//     raw_query/command — raw SQL string as the first positional arg.
//   - clickhouse-driver (native protocol): Client.execute/execute_iter/
//     execute_with_progress — raw SQL string as arg 0.
//
// NOTE (per memory: Python tsflow walker only descends into function bodies):
// every fixture wraps its call site in a `def handler():` block.
// =========================================================================

func TestPython_ClickHouse_SinksRegistered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangPython)
	if cat == nil {
		t.Fatal("Python catalog not loaded")
	}
	found := map[string]bool{}
	for _, s := range cat.Sinks() {
		if s.Category == taint.SnkSQLQuery {
			found[s.ID] = true
		}
	}
	want := []string{
		"py.clickhouse_connect.query_df",
		"py.clickhouse_connect.query_np",
		"py.clickhouse_connect.query_arrow",
		"py.clickhouse_connect.raw_query",
		"py.clickhouse_connect.command",
		"py.clickhouse_driver.execute",
		"py.clickhouse_driver.execute_iter",
		"py.clickhouse_driver.execute_with_progress",
	}
	for _, id := range want {
		if !found[id] {
			t.Errorf("missing expected SnkSQLQuery sink: %s", id)
		}
	}
}

// --- clickhouse-connect (official) ---

func TestPython_ClickHouseConnect_QueryDf_SQLi(t *testing.T) {
	code := `
import clickhouse_connect
from flask import request

def handler():
    region = request.args.get("region")
    client = clickhouse_connect.get_client(host="localhost")
    sql = "SELECT * FROM events WHERE region = '" + region + "'"
    df = client.query_df(sql)
    return df.to_dict("records")
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow: request.args -> client.query_df()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_ClickHouseConnect_QueryNp_SQLi(t *testing.T) {
	code := `
import clickhouse_connect
from flask import request

def handler():
    metric = request.args.get("metric")
    client = clickhouse_connect.get_client(host="localhost")
    arr = client.query_np("SELECT " + metric + " FROM stats")
    return arr.tolist()
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow: request.args -> client.query_np()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_ClickHouseConnect_QueryArrow_SQLi(t *testing.T) {
	code := `
import clickhouse_connect
from flask import request

def handler():
    table = request.args.get("table")
    client = clickhouse_connect.get_client(host="localhost")
    t = client.query_arrow("SELECT * FROM " + table)
    return t
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow: request.args -> client.query_arrow()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_ClickHouseConnect_RawQuery_SQLi(t *testing.T) {
	code := `
import clickhouse_connect
from flask import request

def handler():
    name = request.form.get("name")
    client = clickhouse_connect.get_client(host="localhost")
    raw = client.raw_query("SELECT id FROM users WHERE name = '" + name + "'")
    return raw
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow: request.form -> client.raw_query()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_ClickHouseConnect_Command_SQLi(t *testing.T) {
	code := `
import clickhouse_connect
from flask import request

def handler():
    tbl = request.args.get("tbl")
    client = clickhouse_connect.get_client(host="localhost")
    client.command("DROP TABLE " + tbl)
    return "ok"
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow: request.args -> client.command()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- clickhouse-driver (native protocol) ---

func TestPython_ClickHouseDriver_Execute_SQLi(t *testing.T) {
	code := `
from clickhouse_driver import Client
from flask import request

def handler():
    uid = request.args.get("uid")
    client = Client("localhost")
    rows = client.execute("SELECT * FROM users WHERE id = " + uid)
    return rows
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow: request.args -> client.execute()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_ClickHouseDriver_ExecuteIter_SQLi(t *testing.T) {
	code := `
from clickhouse_driver import Client
from flask import request

def handler():
    col = request.args.get("col")
    client = Client("localhost")
    for row in client.execute_iter("SELECT " + col + " FROM big_table"):
        process(row)
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow: request.args -> client.execute_iter()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_ClickHouseDriver_ExecuteWithProgress_SQLi(t *testing.T) {
	code := `
from clickhouse_driver import Client
from flask import request

def handler():
    f = request.args.get("filter")
    client = Client("localhost")
    rows = client.execute_with_progress("SELECT * FROM logs WHERE msg LIKE '%" + f + "%'")
    return rows
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow: request.args -> client.execute_with_progress()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Negative controls ---

// Parameterized clickhouse-connect query: the tainted value is bound via the
// parameters= kwarg ({name:Type} server-side binding), and the SQL string is a
// constant. No taint flows into the SQL string itself, so no flow expected.
func TestPython_ClickHouseConnect_Parameterized_NoFlow(t *testing.T) {
	code := `
import clickhouse_connect
from flask import request

def handler():
    region = request.args.get("region")
    client = clickhouse_connect.get_client(host="localhost")
    df = client.query_df("SELECT * FROM events WHERE region = {r:String}", parameters={"r": region})
    return df.to_dict("records")
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("unexpected SQL injection flow on parameterized clickhouse-connect query (parameters kwarg is bound): %+v", f)
		}
	}
}

// Constant SQL with clickhouse-driver: no user input reaches the query string.
func TestPython_ClickHouseDriver_ConstantSQL_NoFlow(t *testing.T) {
	code := `
from clickhouse_driver import Client

def handler():
    client = Client("localhost")
    rows = client.execute("SELECT count() FROM events")
    return rows
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("unexpected SQL injection flow on constant clickhouse-driver query: %+v", f)
		}
	}
}

// batou:ignore-end
