package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Python ORM / DB-layer second-order taint sources
// Covers: SQLAlchemy (session.query, Connection.execute, Engine.execute,
// session.scalars/scalar, Result.fetch*) and pymongo (aggregate, distinct,
// find_one_and_*). Data written to a DB by one request and read back later
// is attacker-influenced — these reads are SrcDatabase sources so flows into
// SQL/command/log sinks are detected (CWE-89/78/117 second-order injection).
// =========================================================================

func TestPython_ORMSources_Registered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangPython)
	if cat == nil {
		t.Fatal("Python catalog not loaded")
	}
	sources := cat.Sources()
	found := map[string]bool{}
	for _, s := range sources {
		if s.Category == taint.SrcDatabase {
			found[s.ID] = true
		}
	}
	want := []string{
		"py.sqlalchemy.session.query",
		"py.sqlalchemy.connection.execute",
		"py.sqlalchemy.engine.execute",
		"py.sqlalchemy.session.scalars",
		"py.sqlalchemy.result.fetchall",
		"py.pymongo.aggregate",
		"py.pymongo.distinct",
		"py.pymongo.find_one_and_modify",
	}
	for _, id := range want {
		if !found[id] {
			t.Errorf("missing expected SrcDatabase source: %s", id)
		}
	}
}

// --- Positive baseline: proves the harness is wired (known source -> known sink) ---

func TestPython_ORMSources_Baseline_RequestToSQL(t *testing.T) {
	code := `
from flask import request

def baseline():
    name = request.args.get("name")
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Fatal("baseline broken: expected SQL injection flow from request.args -> cursor.execute()")
	}
}

// --- SQLAlchemy ORM Query ---

func TestPython_SQLAlchemySessionQuery_SQLi(t *testing.T) {
	code := `
def sync_users():
    users = session.query(User).all()
    for u in users:
        cursor.execute("DELETE FROM cache WHERE owner = '" + u.email + "'")
`
	flows := Analyze(code, "/app/sync.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from session.query(...).all() -> cursor.execute()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- SQLAlchemy Core Connection.execute ---

func TestPython_SQLAlchemyConnectionExecute_CommandInjection(t *testing.T) {
	code := `
import os

def run_jobs():
    rows = conn.execute(stmt).fetchall()
    for row in rows:
        os.system(row.command)
`
	flows := Analyze(code, "/app/worker.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from conn.execute(...).fetchall() -> os.system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- SQLAlchemy 1.x Engine.execute (legacy connectionless execution) ---

func TestPython_SQLAlchemyEngineExecute_LogInjection(t *testing.T) {
	code := `
import logging

def audit():
    result = engine.execute(stmt)
    row = result.first()
    logging.info("first row: " + row.name)
`
	flows := Analyze(code, "/app/audit.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow from engine.execute(...).first() -> logging.info()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- SQLAlchemy 2.0 session.scalars()/scalar() ---

func TestPython_SQLAlchemySessionScalars_SQLi(t *testing.T) {
	code := `
def list_users():
    users = session.scalars(select(User)).all()
    for u in users:
        cursor.execute("UPDATE prefs SET seen = 1 WHERE owner = '" + u.email + "'")
`
	flows := Analyze(code, "/app/users.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from session.scalars(...).all() -> cursor.execute()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_SQLAlchemySessionScalar_CommandInjection(t *testing.T) {
	code := `
import os

def get_setting():
    val = session.scalar(select(Setting.shell_cmd))
    os.system(val)
`
	flows := Analyze(code, "/app/settings.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from session.scalar(...) -> os.system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- SQLAlchemy Result row-fetch methods ---

func TestPython_SQLAlchemyResultFetchall_SQLi(t *testing.T) {
	code := `
def replay():
    rows = result.fetchall()
    for row in rows:
        cursor.execute("INSERT INTO audit VALUES ('" + row[0] + "')")
`
	flows := Analyze(code, "/app/replay.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from result.fetchall() -> cursor.execute()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- pymongo aggregate ---

func TestPython_PymongoAggregate_CommandInjection(t *testing.T) {
	code := `
import os

def run_pipeline():
    docs = collection.aggregate(pipeline)
    for doc in docs:
        os.system(doc["cmd"])
`
	flows := Analyze(code, "/app/pipeline.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from collection.aggregate() -> os.system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- pymongo distinct ---

func TestPython_PymongoDistinct_CommandInjection(t *testing.T) {
	code := `
import os

def run_cmds():
    cmds = collection.distinct("shell_cmd")
    for c in cmds:
        os.system(c)
`
	flows := Analyze(code, "/app/cmds.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from collection.distinct() -> os.system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- pymongo find_one_and_* ---

func TestPython_PymongoFindOneAndUpdate_SQLi(t *testing.T) {
	code := `
def claim_job():
    doc = collection.find_one_and_update({"status": "pending"}, {"$set": {"status": "running"}})
    cursor.execute("UPDATE jobs SET note = '" + doc["note"] + "'")
`
	flows := Analyze(code, "/app/jobs.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from collection.find_one_and_update() -> cursor.execute()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Safe pattern: a recognized DB source in scope must not spuriously create
// a flow when only constant data reaches the sink. ---

func TestPython_ORMSources_Safe_ConstantQuery_NoFlow(t *testing.T) {
	code := `
def safe_constant():
    users = session.query(User).all()
    # The query string is a constant literal; nothing from 'users' reaches the sink.
    cursor.execute("SELECT * FROM audit_log WHERE action = 'login'")
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("unexpected SQL injection flow on constant-only query: %+v", f)
		}
	}
}
