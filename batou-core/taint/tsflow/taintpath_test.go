package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// A multi-hop Python flow (request source → intermediate vars → SQL sink)
// should produce a structured TaintPath on the resulting finding with at
// least source + one propagation + sink, all in the same file, with
// non-decreasing line numbers from source to sink.
func TestTaintPath_PythonMultiHop(t *testing.T) {
	code := `
from flask import request

async def handler():
    name = request.args.get("name")
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    q2 = query
    await conn.execute(q2)
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Fatalf("expected SQL injection flow; got %d flows", len(flows))
	}

	var found bool
	for _, fl := range flows {
		if fl.Sink.Category != taint.SnkSQLQuery {
			continue
		}
		f := fl.ToFinding()
		if len(f.TaintPath) < 3 {
			t.Logf("flow has only %d path steps: %+v", len(f.TaintPath), f.TaintPath)
			continue
		}
		found = true
		if f.TaintPath[0].Kind != rules.TaintStepSource {
			t.Errorf("first step kind = %q, want source", f.TaintPath[0].Kind)
		}
		if f.TaintPath[len(f.TaintPath)-1].Kind != rules.TaintStepSink {
			t.Errorf("last step kind = %q, want sink", f.TaintPath[len(f.TaintPath)-1].Kind)
		}
		for i, s := range f.TaintPath {
			if s.File != "/app/views.py" {
				t.Errorf("step %d file = %q, want /app/views.py", i, s.File)
			}
			if s.Line <= 0 {
				t.Errorf("step %d has non-positive line %d", i, s.Line)
			}
		}
		for i := 1; i < len(f.TaintPath); i++ {
			if f.TaintPath[i].Line < f.TaintPath[i-1].Line {
				t.Errorf("step %d line %d < prev step line %d", i, f.TaintPath[i].Line, f.TaintPath[i-1].Line)
			}
		}
	}
	if !found {
		t.Errorf("no SQL flow produced a TaintPath with >= 3 steps; flows=%d", len(flows))
	}
}
