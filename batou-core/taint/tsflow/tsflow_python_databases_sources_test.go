package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Python encode/databases second-order read sources
// Rows read back from the DB are attacker-controlled when a prior request
// stored user input (stored/second-order taint). The fetch_* / iterate
// return values flow into downstream sinks without re-validation.
// Complements the existing py.databases.* SQL-injection sinks.
// =========================================================================

func TestPython_Databases_SourcesRegistered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangPython)
	if cat == nil {
		t.Fatal("Python catalog not loaded")
	}
	found := map[string]bool{}
	for _, s := range cat.Sources() {
		if s.Category == taint.SrcDatabase {
			found[s.ID] = true
		}
	}
	want := []string{
		"py.databases.fetch_all",
		"py.databases.fetch_one",
		"py.databases.fetch_val",
		"py.databases.iterate",
	}
	for _, id := range want {
		if !found[id] {
			t.Errorf("missing expected SrcDatabase source: %s", id)
		}
	}
}

// fetch_val returns a scalar directly — cleanest second-order flow.
func TestPython_Databases_FetchVal_SecondOrder_Command(t *testing.T) {
	code := `
import os

async def run():
    host = await database.fetch_val("SELECT host FROM targets LIMIT 1")
    os.system("ping " + host)
`
	flows := Analyze(code, "/app/jobs.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected second-order command-injection flow from database.fetch_val() -> os.system()")
		for _, f := range flows {
			t.Logf("  flow: %s (%s) -> %s (%s) conf=%.2f", f.Source.Category, f.Source.ID, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestPython_Databases_FetchOne_SecondOrder_Command(t *testing.T) {
	code := `
import os

async def run():
    row = await database.fetch_one("SELECT cmd FROM jobs LIMIT 1")
    os.system("sh -c " + row["cmd"])
`
	flows := Analyze(code, "/app/jobs.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected second-order command-injection flow from database.fetch_one() -> os.system()")
		for _, f := range flows {
			t.Logf("  flow: %s (%s) -> %s (%s) conf=%.2f", f.Source.Category, f.Source.ID, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestPython_Databases_FetchAll_SecondOrder_Command(t *testing.T) {
	code := `
import os

async def run():
    rows = await database.fetch_all("SELECT name FROM hosts")
    for row in rows:
        os.system("nslookup " + row["name"])
`
	flows := Analyze(code, "/app/jobs.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected second-order command-injection flow from database.fetch_all() -> os.system()")
		for _, f := range flows {
			t.Logf("  flow: %s (%s) -> %s (%s) conf=%.2f", f.Source.Category, f.Source.ID, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestPython_Databases_Iterate_SecondOrder_Command(t *testing.T) {
	code := `
import os

async def run():
    async for row in database.iterate("SELECT name FROM hosts"):
        os.system("nslookup " + row["name"])
`
	flows := Analyze(code, "/app/jobs.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected second-order command-injection flow from database.iterate() -> os.system()")
		for _, f := range flows {
			t.Logf("  flow: %s (%s) -> %s (%s) conf=%.2f", f.Source.Category, f.Source.ID, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

// `db` receiver also matches via the matcher's database heuristic.
func TestPython_Databases_DbReceiver_SecondOrder_Command(t *testing.T) {
	code := `
import os

async def run():
    host = await db.fetch_val("SELECT host FROM targets LIMIT 1")
    os.system("ping " + host)
`
	flows := Analyze(code, "/app/jobs.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected second-order command-injection flow from db.fetch_val() -> os.system()")
		for _, f := range flows {
			t.Logf("  flow: %s (%s) -> %s (%s) conf=%.2f", f.Source.Category, f.Source.ID, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

// Negative control: a constant value (no DB read) must not produce a flow.
func TestPython_Databases_ConstantValue_NoFlow(t *testing.T) {
	code := `
import os

async def run():
    host = "127.0.0.1"
    os.system("ping " + host)
`
	flows := Analyze(code, "/app/jobs.py", rules.LangPython)
	for _, f := range flows {
		if f.Source.Category == taint.SrcDatabase {
			t.Errorf("unexpected SrcDatabase flow on constant value: %+v", f)
		}
	}
}
