package tsflow

// Permanent regression tests for the cross-method / cross-function STORED-STATE
// taint channel (field_global_state.go).
//
// Before this channel existed, tsflow modelled only param->return threading, so
// taint stored in one scope and read in another was silently dropped:
//
//	self.x = source() in method A; sink(self.x) in method B  -> 0 flows (FN)
//	global g set in function A;     sink(g) in function B     -> 0 flows (FN)
//
// These tests pin the FN fix (0 -> 1) AND the FP discipline that keeps it sound:
// a field/global written only with a constant never becomes a source, sibling
// fields stay distinct, and a function-local `obj.attr` (base is not an instance
// receiver) does NOT leak across function boundaries.

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// --- Positive: cross-method instance field (the canonical OO web-handler vuln) ---

func TestCrossMethodField_Python_Fires(t *testing.T) {
	code := `
from flask import request

class H:
    def a(self):
        self.q = request.args.get('q')
    def b(self):
        cursor.execute(self.q)
`
	flows := Analyze(code, "/app/h.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("expected cross-method field flow self.q=src in a() -> execute(self.q) in b()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestCrossMethodField_JS_Fires(t *testing.T) {
	code := `
class H {
    a(req) {
        this.q = req.query.q;
    }
    b() {
        db.query(this.q);
    }
}
`
	flows := Analyze(code, "/app/h.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("expected JS cross-method field flow this.q=req.query.q -> db.query(this.q)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestCrossMethodField_Java_Fires(t *testing.T) {
	code := `
public class H {
    private String q;
    public void a(javax.servlet.http.HttpServletRequest request) {
        this.q = request.getParameter("q");
    }
    public void b(java.sql.Statement stmt) throws Exception {
        stmt.executeQuery(this.q);
    }
}
`
	flows := Analyze(code, "/app/H.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("expected Java cross-method field flow this.q=getParameter -> executeQuery(this.q)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// --- Positive: module global set in one function, read in another ---

func TestModuleGlobal_Python_Fires(t *testing.T) {
	code := `
from flask import request

g = None

def store():
    global g
    g = request.args.get('q')

def use():
    cursor.execute(g)
`
	flows := Analyze(code, "/app/g.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("expected module-global flow: g set under `global g` in store() -> execute(g) in use()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// --- FP discipline: constant-only field/global must NOT become a source ---

func TestCrossMethodField_Python_ConstFieldNoFlow(t *testing.T) {
	code := `
class H:
    def a(self):
        self.q = "constant"
    def b(self):
        cursor.execute(self.q)
`
	flows := Analyze(code, "/app/h.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("FP: constant-only self.q became a source; got %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// A field tainted in one method must not bleed onto a SIBLING field read in
// another method (field-sensitivity is preserved across the scope boundary).
func TestCrossMethodField_Python_SiblingFieldNoFlow(t *testing.T) {
	code := `
from flask import request

class H:
    def a(self):
        self.q = request.args.get('q')
        self.y = "safe"
    def b(self):
        cursor.execute(self.y)
`
	flows := Analyze(code, "/app/h.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("FP: sibling self.y (constant) became a source; got %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestCrossMethodField_JS_SiblingFieldNoFlow(t *testing.T) {
	code := `
class H {
    a(req) { this.q = req.query.q; this.y = "safe"; }
    b() { db.query(this.y); }
}
`
	flows := Analyze(code, "/app/h.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("FP: JS sibling this.y became a source; got %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestModuleGlobal_Python_ConstGlobalNoFlow(t *testing.T) {
	code := `
g = "constant"

def use():
    cursor.execute(g)
`
	flows := Analyze(code, "/app/g.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("FP: constant global g became a source; got %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// A function-local `obj.attr` (base is NOT an instance receiver) is
// function-scoped and must not carry taint across function boundaries — only
// self/this-rooted fields are file-level stored state.
func TestCrossMethodField_Python_LocalObjNoCrossFnLeak(t *testing.T) {
	code := `
from flask import request

def a():
    obj.q = request.args.get('q')

def b():
    cursor.execute(obj.q)
`
	flows := Analyze(code, "/app/h.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("FP: function-local obj.q leaked across functions; got %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// A field written from a CONSTRUCTOR PARAMETER (not a genuine catalog source)
// must NOT become a file-level stored source. This is the real-world Django FP
// shape (`def __init__(self, data): self._store = data` then `self._store` read
// in other methods): the param's taint is relative to the caller and is modelled
// by the param->return summary, so promoting `self._store` to a file-level
// source over-taints every read of it across the class. Pin it: a plain helper
// class that stores a param onto self and later uses it in a sink produces no
// stored-state flow (the param is not auto-tainted in the harvest walk).
func TestCrossMethodField_Python_ParamStoredFieldNoFlow(t *testing.T) {
	code := `
class Store:
    def __init__(self, data):
        self._store = data
    def remove(self, item):
        os.remove(self._store)
`
	flows := Analyze(code, "/app/store.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileWrite || f.Sink.Category == taint.SnkFileRead {
			t.Errorf("FP: param-stored self._store became a file-level source; got %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// A module global that is locally rebound to a safe value before the read in the
// SAME function must clear the seeded taint (strong-update over the seed).
func TestModuleGlobal_Python_LocalRebindClearsSeed(t *testing.T) {
	code := `
from flask import request

g = None

def store():
    global g
    g = request.args.get('q')

def use():
    g = "safe"
    cursor.execute(g)
`
	flows := Analyze(code, "/app/g.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("FP: local safe rebinding of g should clear seeded global taint; got %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}
