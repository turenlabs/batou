package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// These tests cover the JS/TS for...of / for...in (for_in_statement) recall gap:
// the loop binding must inherit taint from a tainted (or source) iterable so
// that `for (const item of req.body.items) { sink(item) }` is detected. Before
// the processJSForOf walker handler, for_in_statement was not seeded (only
// Java enhanced_for_statement and Python for_statement were), so every loop
// variant below produced zero flows while its non-loop baseline fired.

func TestJS_ForOf_SQLInjection(t *testing.T) {
	code := `
function handler(req, res) {
    const items = req.body.items;
    for (const item of items) {
        db.query(item);
    }
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for req.body.items -> for...of -> db.query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJS_ForOf_InlineIterable_SQLInjection(t *testing.T) {
	// Iterable is the source expression directly (no intermediate variable).
	code := `
function handler(req, res) {
    for (const item of req.body.items) {
        db.query(item);
    }
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for inline req.body.items -> for...of -> db.query")
	}
}

func TestJS_ForOf_CommandInjection(t *testing.T) {
	code := `
const { exec } = require('child_process');

function handler(req, res) {
    for (const cmd of req.query.cmds) {
        exec(cmd);
    }
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for req.query.cmds -> for...of -> exec")
	}
}

func TestJS_ForOf_Destructuring_SQLInjection(t *testing.T) {
	// Destructuring binding: each name is derived from a tainted element.
	code := `
function handler(req, res) {
    for (const [key, value] of req.body.pairs) {
        db.query(value);
    }
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for destructured for...of value -> db.query")
	}
}

func TestTS_ForOf_SQLInjection(t *testing.T) {
	code := `
function handler(req: any, res: any) {
    const items: string[] = req.query.items;
    for (const item of items) {
        db.query(item);
    }
}
`
	flows := Analyze(code, "/app/handler.ts", rules.LangTypeScript)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for TS req.query.items -> for...of -> db.query")
	}
}

func TestJS_ForOf_ConstantIterable_NoFlow(t *testing.T) {
	// Iterating a constant literal array must NOT produce a flow.
	code := `
function handler(req, res) {
    const items = ["alpha", "beta", "gamma"];
    for (const item of items) {
        db.query(item);
    }
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did not expect SQL injection flow for constant array iterable")
	}
}

func TestJS_ForIn_ConstantObject_NoFlow(t *testing.T) {
	// for...in over a constant object yields constant keys — no flow.
	code := `
function handler(req, res) {
    const obj = {a: 1, b: 2};
    for (const k in obj) {
        db.query(k);
    }
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did not expect SQL injection flow for constant object for...in")
	}
}
