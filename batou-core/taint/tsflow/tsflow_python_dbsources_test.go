package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Python database sources — second-order injection via DB read results
// =========================================================================

func TestPython_DB_SourcesRegistered(t *testing.T) {
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
		"py.cursor.fetchone",
		"py.django.objects.get",
		"py.django.objects.filter",
		"py.django.values_list",
		"py.sqlalchemy.session.execute",
		"py.sqlalchemy.result.scalars",
		"py.pymongo.find_one",
		"py.pymongo.find",
		"py.peewee.get",
		"py.pandas.read_sql",
		"py.pandas.read_sql_query",
	}
	for _, id := range want {
		if !found[id] {
			t.Errorf("missing expected SrcDatabase source: %s", id)
		}
	}
}

// --- Django ORM ---

func TestPython_DjangoObjectsGet_SQLi(t *testing.T) {
	code := `
def view():
    user = User.objects.get(pk=1)
    cursor.execute("SELECT * FROM logs WHERE name = '" + user.name + "'")
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from objects.get() result -> cursor.execute()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_DjangoObjectsFilter_CommandInjection(t *testing.T) {
	code := `
import os

def process_tasks():
    tasks = Task.objects.filter(status="pending")
    for task in tasks:
        os.system(task.command)
`
	flows := Analyze(code, "/app/tasks.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from objects.filter() -> os.system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_DjangoValuesList_Eval(t *testing.T) {
	code := `
def run_expressions():
    exprs = QuerySet.values_list("expr", flat=True)
    for expr in exprs:
        eval(expr)
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval injection flow from values_list() -> eval()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- SQLAlchemy ---

func TestPython_SQLAlchemySessionExecute_CommandInjection(t *testing.T) {
	code := `
import os

def run_from_db(session):
    result = session.execute(stmt)
    row = result.fetchone()
    os.system(row.command)
`
	flows := Analyze(code, "/app/db.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from session.execute() -> os.system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_SQLAlchemyScalars_CommandInjection(t *testing.T) {
	code := `
import os

def run_jobs(session):
    jobs = session.execute(stmt).scalars().all()
    for job in jobs:
        os.system(job.command)
`
	flows := Analyze(code, "/app/worker.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from scalars().all() -> os.system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- pymongo ---

func TestPython_PymongoFindOne_SQLi(t *testing.T) {
	code := `
def sync_user():
    doc = collection.find_one({"active": True})
    cursor.execute("INSERT INTO users VALUES ('" + doc["name"] + "')")
`
	flows := Analyze(code, "/app/sync.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from collection.find_one() -> cursor.execute()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_PymongoFind_CommandInjection(t *testing.T) {
	code := `
import os

def run_commands():
    docs = collection.find({"type": "job"})
    for doc in docs:
        os.system(doc["cmd"])
`
	flows := Analyze(code, "/app/runner.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from collection.find() -> os.system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Peewee ORM ---

func TestPython_PeeweeGetOrNone_CommandInjection(t *testing.T) {
	code := `
import os

def execute_job(job_id):
    job = Job.get_or_none(Job.id == job_id)
    os.system(job.command)
`
	flows := Analyze(code, "/app/jobs.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from get_or_none() -> os.system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- pandas ---

func TestPython_PandasReadSql_Eval(t *testing.T) {
	code := `
import pandas

def run_formulas(conn):
    df = pandas.read_sql("SELECT formula FROM calculations", conn)
    eval(df)
`
	flows := Analyze(code, "/app/calc.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval injection flow from pd.read_sql() -> eval()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Safe patterns (documents expected behavior) ---

func TestPython_DjangoObjectsGet_Safe_Parameterized(t *testing.T) {
	code := `
def view():
    user = User.objects.get(pk=1)
    cursor.execute("SELECT * FROM logs WHERE username = %s", [user.name])
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	// Parameterized queries should still show a flow (the source is tainted),
	// but this documents the expected behavior.
	for _, f := range flows {
		t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
	}
}
