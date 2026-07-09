package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Tests for Python Neo4j Cypher injection sinks (CWE-943).
// The official neo4j-python-driver (v5+), py2neo, and neomodel execute Cypher
// via driver.execute_query / graph.evaluate / db.cypher_query. Building the
// Cypher string from user input allows Cypher injection. Safe code passes
// values via keyword args or a parameters dict.

// --- Official neo4j driver v5+: driver.execute_query ---

func TestPython_Neo4j_Driver_ExecuteQuery_Injection(t *testing.T) {
	code := `
from flask import Flask, request
from neo4j import GraphDatabase

app = Flask(__name__)
driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "pw"))

@app.route("/search")
def search():
    term = request.args.get("q")
    cypher = f"MATCH (n) WHERE n.title CONTAINS '{term}' RETURN n"
    records, summary, keys = driver.execute_query(cypher, database_="neo4j")
    return str(records)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Cypher-injection flow for request.args -> driver.execute_query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- py2neo: graph.evaluate ---

func TestPython_Py2neo_Graph_Evaluate_Injection(t *testing.T) {
	code := `
from flask import Flask, request
from py2neo import Graph

app = Flask(__name__)
graph = Graph("bolt://localhost:7687", auth=("neo4j", "pw"))

@app.route("/count")
def count():
    label = request.args.get("label")
    cypher = "MATCH (n:" + label + ") RETURN count(n)"
    total = graph.evaluate(cypher)
    return str(total)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Cypher-injection flow for request.args -> graph.evaluate (py2neo)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- neomodel: db.cypher_query ---

func TestPython_Neomodel_Db_CypherQuery_Injection(t *testing.T) {
	code := `
from flask import Flask, request
from neomodel import db

app = Flask(__name__)

@app.route("/post")
def find_post():
    title = request.args.get("title")
    cypher = "MATCH (p:Post) WHERE p.title = '" + title + "' RETURN p"
    results, meta = db.cypher_query(cypher)
    return str(results)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Cypher-injection flow for request.args -> db.cypher_query (neomodel)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Safe: parameterized Cypher with keyword argument on execute_query ---

func TestPython_Neo4j_Driver_ExecuteQuery_Parameterized_NoFlow(t *testing.T) {
	code := `
from flask import Flask, request
from neo4j import GraphDatabase

app = Flask(__name__)
driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "pw"))

@app.route("/search")
def search():
    term = request.args.get("q")
    records, summary, keys = driver.execute_query(
        "MATCH (n) WHERE n.title CONTAINS $term RETURN n",
        term=term,
        database_="neo4j",
    )
    return str(records)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.ID == "py.neo4j.driver.execute_query" {
			t.Errorf("expected NO Cypher-injection flow when Cypher is a literal and values are passed via kwargs, got sink=%s", f.Sink.ID)
		}
	}
}

// --- Safe: parameterized Cypher with params dict on db.cypher_query ---

func TestPython_Neomodel_Db_CypherQuery_Parameterized_NoFlow(t *testing.T) {
	code := `
from flask import Flask, request
from neomodel import db

app = Flask(__name__)

@app.route("/post")
def find_post():
    title = request.args.get("title")
    results, meta = db.cypher_query(
        "MATCH (p:Post) WHERE p.title = $title RETURN p",
        params={"title": title},
    )
    return str(results)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.ID == "py.neomodel.db.cypher_query" {
			t.Errorf("expected NO Cypher-injection flow when Cypher is a literal and values are passed via params dict, got sink=%s", f.Sink.ID)
		}
	}
}

// --- Safe: hardcoded Cypher literal ---

func TestPython_Neo4j_Driver_ExecuteQuery_Hardcoded_NoFlow(t *testing.T) {
	code := `
from neo4j import GraphDatabase

driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "pw"))

def list_users():
    records, summary, keys = driver.execute_query(
        "MATCH (n:User {name: 'bob'}) RETURN n",
        database_="neo4j",
    )
    return records
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.ID == "py.neo4j.driver.execute_query" {
			t.Errorf("expected NO Cypher-injection flow for hardcoded Cypher literal, got sink=%s", f.Sink.ID)
		}
	}
}
