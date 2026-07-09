package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Python asyncpg Pool second-order read sources (SrcDatabase).
//
// asyncpg's Pool exposes the same fetch/fetchrow/fetchval read API as a
// Connection, without an explicit acquire() — the dominant idiom in FastAPI
// apps that keep a single module-level `pool = await asyncpg.create_pool()`.
// Rows read back through the Pool are attacker-influenced stored data
// (second-order taint), exactly like the Connection reads already modelled by
// py.asyncpg.fetch. These tests pin the new py.asyncpg.pool.fetch source.
//
// NOTE: like the existing asyncpg Connection source test
// (TestPython_Asyncpg_Fetch_CommandInj), the fixtures omit `await` on the
// source RHS — Python `await`-unwrapping on the source-assignment path is not
// yet in the tsflow walker. The production regex-fallback path handles await.
// =========================================================================

func TestPython_AsyncpgPool_SourceRegistered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangPython)
	if cat == nil {
		t.Fatal("Python catalog not loaded")
	}
	var found *taint.SourceDef
	for i := range cat.Sources() {
		if cat.Sources()[i].ID == "py.asyncpg.pool.fetch" {
			found = &cat.Sources()[i]
			break
		}
	}
	if found == nil {
		t.Fatal("py.asyncpg.pool.fetch source not found in catalog")
	}
	if found.Category != taint.SrcDatabase {
		t.Errorf("py.asyncpg.pool.fetch should be SrcDatabase, got %s", found.Category)
	}
	if found.ObjectType != "asyncpg.Pool" {
		t.Errorf("py.asyncpg.pool.fetch should scope to asyncpg.Pool, got %q", found.ObjectType)
	}
}

// pool.fetchval() returns a single stored value; it flows to os.system().
func TestPython_AsyncpgPool_Fetchval_CommandInj(t *testing.T) {
	code := `
import os

def run_pending(pool):
    cmd = pool.fetchval("SELECT cmd FROM jobs WHERE id = 1")
    os.system(cmd)
`
	flows := Analyze(code, "/app/jobs.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from asyncpg pool.fetchval() -> os.system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// pool.fetch() returns a list of rows; iterating and subscripting a row
// propagates taint to the sink.
func TestPython_AsyncpgPool_Fetch_CommandInj(t *testing.T) {
	code := `
import os

def process_commands(pool):
    rows = pool.fetch("SELECT cmd FROM jobs WHERE status = 'pending'")
    for row in rows:
        os.system(row["cmd"])
`
	flows := Analyze(code, "/app/jobs.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from asyncpg pool.fetch() -> os.system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Scoping / FP-safety: a .fetchval() on a receiver that is neither `pool`
// (asyncpg.Pool) nor `conn` (asyncpg.Connection) must NOT be treated as a
// database read source — no flow should reach os.system().
func TestPython_AsyncpgPool_UnscopedReceiver_NoFlow(t *testing.T) {
	code := `
import os

def loader(widget):
    val = widget.fetchval("SELECT label FROM widgets WHERE id = 1")
    os.system(val)
`
	flows := Analyze(code, "/app/widgets.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand && f.Source.ID == "py.asyncpg.pool.fetch" {
			t.Errorf("unexpected flow: py.asyncpg.pool.fetch matched a non-pool receiver: %+v", f)
		}
	}
}
