package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Tests for Python Apache Cassandra / ScyllaDB / DataStax / Astra DB
// CQL-injection sinks (CWE-943). DataStax cassandra-driver is the canonical
// Python client; building CQL by string concatenation/f-string and passing it
// to SimpleStatement / Session.execute_async / cassandra.concurrent.* allows
// server-side query injection. The safe form is a literal CQL with `?`
// placeholders and a separate parameters tuple/list.

func TestPython_Cassandra_SinksRegistered(t *testing.T) {
	sinks := taint.SinksForLanguage(rules.LangPython)
	want := []string{
		"py.cassandra.simplestatement",
		"py.cassandra.session.execute_async",
		"py.cassandra.execute_concurrent",
		"py.cassandra.execute_concurrent_with_args",
	}
	for _, id := range want {
		found := false
		for _, s := range sinks {
			if s.ID == id {
				found = true
				if s.Category != taint.SnkNoSQL {
					t.Errorf("sink %s: expected SnkSQLQuery, got %v", id, s.Category)
				}
				break
			}
		}
		if !found {
			t.Errorf("expected sink %s to be registered for Python", id)
		}
	}
}

// --- SimpleStatement(cql) — cassandra.query.SimpleStatement constructor ---

func TestPython_Cassandra_SimpleStatement_CQLi(t *testing.T) {
	code := `
from flask import Flask, request
from cassandra.cluster import Cluster
from cassandra.query import SimpleStatement

app = Flask(__name__)
cluster = Cluster(["127.0.0.1"])
session = cluster.connect("ks")

@app.route("/users")
def list_users():
    role = request.args.get("role")
    cql = "SELECT id, name FROM users WHERE role = '" + role + "'"
    stmt = SimpleStatement(cql)
    rows = session.execute(stmt)
    return str(list(rows))
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected CQL-injection flow for request.args -> SimpleStatement(concat)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- session.execute_async(cql) — async hot path ---

func TestPython_Cassandra_Session_ExecuteAsync_CQLi(t *testing.T) {
	code := `
from fastapi import FastAPI, Request
from cassandra.cluster import Cluster

app = FastAPI()
cluster = Cluster(["127.0.0.1"])
session = cluster.connect("ks")

@app.get("/orders")
async def get_orders(request: Request):
    customer = request.query_params.get("customer")
    cql = f"SELECT * FROM orders WHERE customer_id = '{customer}' ALLOW FILTERING"
    future = session.execute_async(cql)
    rows = future.result()
    return list(rows)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected CQL-injection flow for request.query_params -> session.execute_async(f-string)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- cassandra.concurrent.execute_concurrent(session, statements_and_params) ---

func TestPython_Cassandra_ExecuteConcurrent_CQLi(t *testing.T) {
	code := `
from flask import Flask, request
from cassandra.cluster import Cluster
from cassandra.concurrent import execute_concurrent

app = Flask(__name__)
cluster = Cluster(["127.0.0.1"])
session = cluster.connect("ks")

@app.route("/bulk", methods=["POST"])
def bulk_insert():
    raw = request.json
    statements_and_params = []
    for item in raw["items"]:
        cql = "INSERT INTO items (id, name) VALUES (" + str(item["id"]) + ", '" + item["name"] + "')"
        statements_and_params.append((cql, ()))
    results = execute_concurrent(session, statements_and_params, raise_on_first_error=False)
    return {"ok": True}
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected CQL-injection flow for request.json -> execute_concurrent(concat)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- cassandra.concurrent.execute_concurrent_with_args(session, statement, parameters) ---

func TestPython_Cassandra_ExecuteConcurrentWithArgs_CQLi(t *testing.T) {
	code := `
from flask import Flask, request
from cassandra.cluster import Cluster
from cassandra.concurrent import execute_concurrent_with_args

app = Flask(__name__)
cluster = Cluster(["127.0.0.1"])
session = cluster.connect("ks")

@app.route("/bulk-by-name")
def bulk_by_name():
    column = request.args.get("col")
    cql = "SELECT * FROM users WHERE " + column + " = ?"
    params = [(n,) for n in request.args.getlist("name")]
    results = execute_concurrent_with_args(session, cql, params)
    return str(results)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected CQL-injection flow for request.args -> execute_concurrent_with_args (statement arg)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Safe: parameterized CQL with ? placeholders + separate parameters tuple ---
// Verifies the new sinks do NOT fire when CQL is a literal string and tainted
// values are passed via the parameters argument. This locks in the canonical
// safe pattern from the DataStax docs.

func TestPython_Cassandra_SafeParameterized_NoFlow(t *testing.T) {
	code := `
from flask import Flask, request
from cassandra.cluster import Cluster
from cassandra.query import SimpleStatement

app = Flask(__name__)
cluster = Cluster(["127.0.0.1"])
session = cluster.connect("ks")

@app.route("/users-safe")
def list_users_safe():
    role = request.args.get("role")
    stmt = SimpleStatement("SELECT id, name FROM users WHERE role = ?")
    future = session.execute_async(stmt, (role,))
    rows = future.result()
    return str(list(rows))
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		switch f.Sink.ID {
		case "py.cassandra.simplestatement",
			"py.cassandra.session.execute_async":
			t.Errorf("expected NO CQL-injection flow when CQL is a literal and the tainted value is passed via parameters tuple, got sink=%s", f.Sink.ID)
		}
	}
}
