package graph

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// TestBuildPythonLambdaInDecoratorArg covers the canonical Flask
// pattern: `app.add_url_rule('/x', view_func=lambda: get_query())`.
// Both the outer function (which receives `app`) and the lambda closure
// must exist as separate FuncNodes; calls inside the lambda body
// (get_query) must be attributed to the closure, not the outer.
//
// Uses a bare-identifier call in the lambda body because
// pythonCallText() rejects chained attributes (request.args.get) — we
// pin the closure-attribution behavior on a call form the resolver
// actually emits.
func TestBuildPythonLambdaInDecoratorArg(t *testing.T) {
	cg := NewCallGraph("/project", "s1")

	content := `def register(app):
    app.add_url_rule('/x', view_func=lambda: get_query())
`
	updated := buildPythonNodes(cg, "/project/views.py", content, nil)
	if len(updated) < 2 {
		t.Fatalf("expected at least 2 updated nodes (outer + closure), got %d: %v", len(updated), updated)
	}

	outer := cg.GetNode("/project/views.py:register")
	if outer == nil {
		t.Fatal("expected outer register node")
	}

	// Outer's RawCalls should contain "app.add_url_rule" but NOT
	// "get_query" — that call lives inside the lambda body.
	if !containsRawCall(outer, "app.add_url_rule") {
		t.Errorf("outer.RawCalls = %v, want to include app.add_url_rule", outer.RawCalls)
	}
	if containsRawCall(outer, "get_query") {
		t.Errorf("outer.RawCalls = %v, must NOT include get_query (lambda body)", outer.RawCalls)
	}

	// Find the lambda closure node.
	closure := findPythonClosureNode(cg, "/project/views.py", "register")
	if closure == nil {
		t.Fatal("expected one lambda closure under register")
	}
	if !strings.Contains(closure.Name, ".lambda@") {
		t.Errorf("closure name = %q, want to contain .lambda@", closure.Name)
	}
	if closure.FilePath != "/project/views.py" {
		t.Errorf("closure FilePath = %q, want /project/views.py", closure.FilePath)
	}
	if closure.Language != rules.LangPython {
		t.Errorf("closure Language = %q, want LangPython", closure.Language)
	}
	if closure.StartLine == 0 || closure.EndLine == 0 {
		t.Errorf("closure StartLine=%d EndLine=%d, want both > 0", closure.StartLine, closure.EndLine)
	}

	// Synthetic edge: outer.Calls contains the closure ID,
	// closure.CalledBy contains the outer ID.
	if !containsString(outer.Calls, closure.ID) {
		t.Errorf("outer.Calls = %v, want to include closure ID %q", outer.Calls, closure.ID)
	}
	if !containsString(closure.CalledBy, outer.ID) {
		t.Errorf("closure.CalledBy = %v, want to include outer ID %q", closure.CalledBy, outer.ID)
	}

	// The closure's RawCalls contains get_query.
	if !containsRawCall(closure, "get_query") {
		t.Errorf("closure.RawCalls = %v, want to include get_query", closure.RawCalls)
	}
}

// TestBuildPythonNestedDef covers the factory-returns-handler pattern:
// `def factory(ctrl): def inner(req): db.execute(req.args['q']); return inner`.
// Both `factory` and the nested `inner` closure must exist as separate
// FuncNodes; the db.execute call must belong to inner.
func TestBuildPythonNestedDef(t *testing.T) {
	cg := NewCallGraph("/project", "s2")

	content := `def factory(ctrl):
    def inner(req):
        db.execute(req.args['q'])
    return inner
`
	buildPythonNodes(cg, "/project/factory.py", content, nil)

	outer := cg.GetNode("/project/factory.py:factory")
	if outer == nil {
		t.Fatal("expected factory node")
	}

	// Outer must NOT have db.execute in its RawCalls — that call is
	// inside the nested def.
	if containsRawCall(outer, "db.execute") {
		t.Errorf("factory.RawCalls = %v, must NOT include db.execute (inner body)", outer.RawCalls)
	}

	// Locate the nested-def closure.
	closure := findPythonClosureNode(cg, "/project/factory.py", "factory")
	if closure == nil {
		t.Fatal("expected one nested-def closure under factory")
	}
	if !strings.Contains(closure.Name, ".inner@") {
		t.Errorf("closure name = %q, want to contain .inner@", closure.Name)
	}
	if !containsRawCall(closure, "db.execute") {
		t.Errorf("closure.RawCalls = %v, want to include db.execute", closure.RawCalls)
	}

	// Synthetic edge from factory to inner closure.
	if !containsString(outer.Calls, closure.ID) {
		t.Errorf("factory.Calls = %v, want to include closure ID %q", outer.Calls, closure.ID)
	}

	// `return inner` should attribute to factory (it's a bare
	// identifier reference; not a call expression).
}

// TestBuildPythonClosureDeterministicID pins that the same source
// produces the same closure FuncNode ID across runs — required for the
// persisted call graph to round-trip stably.
func TestBuildPythonClosureDeterministicID(t *testing.T) {
	content := `def f():
    return lambda x: g(x)

def g(x):
    return x
`
	cg1 := NewCallGraph("/project", "s1")
	buildPythonNodes(cg1, "/project/x.py", content, nil)
	cg2 := NewCallGraph("/project", "s2")
	buildPythonNodes(cg2, "/project/x.py", content, nil)

	c1 := findPythonClosureNode(cg1, "/project/x.py", "f")
	c2 := findPythonClosureNode(cg2, "/project/x.py", "f")
	if c1 == nil || c2 == nil {
		t.Fatal("expected lambda closure in both graphs")
	}
	if c1.ID != c2.ID {
		t.Errorf("closure IDs differ across runs: %q vs %q", c1.ID, c2.ID)
	}
}

// TestBuildPythonNestedClosures covers a lambda inside a nested def
// inside a top-level def — each layer must produce its own closure
// node, and a call in the innermost body belongs to the innermost
// closure (not any of its ancestors).
func TestBuildPythonNestedClosures(t *testing.T) {
	cg := NewCallGraph("/project", "s3")

	content := `def outer():
    def middle():
        return lambda: target()
    return middle
`
	buildPythonNodes(cg, "/project/n.py", content, nil)

	outer := cg.GetNode("/project/n.py:outer")
	if outer == nil {
		t.Fatal("expected outer node")
	}

	// We expect 3 nodes total under /project/n.py: outer, middle
	// (nested-def), and the lambda inside middle.
	nodes := cg.NodesInFile("/project/n.py")
	if len(nodes) != 3 {
		names := []string{}
		for _, n := range nodes {
			names = append(names, n.Name)
		}
		t.Fatalf("expected 3 nodes (outer + middle closure + lambda closure), got %d: %v", len(nodes), names)
	}

	// Find the innermost closure (the lambda) — it should be the
	// only node with target() in its RawCalls.
	var innermost *FuncNode
	for _, n := range nodes {
		if containsRawCall(n, "target") {
			if innermost != nil {
				t.Fatalf("multiple nodes claim target(): %q and %q", innermost.Name, n.Name)
			}
			innermost = n
		}
	}
	if innermost == nil {
		t.Fatal("no node claims the target() call")
	}
	// The lambda is inside middle, so its name should have the middle
	// closure's anchor as a prefix.
	if !strings.Contains(innermost.Name, ".lambda@") {
		t.Errorf("innermost.Name = %q, want to contain .lambda@", innermost.Name)
	}
	if !strings.Contains(innermost.Name, ".middle@") {
		t.Errorf("innermost.Name = %q, want to contain .middle@ (nested under middle)", innermost.Name)
	}
}

// TestBuildPythonClassMethodLambda covers the case where a method
// contains a lambda — the closure name must use the qualified method
// name as its prefix ("Cls.method.lambda@L:C").
func TestBuildPythonClassMethodLambda(t *testing.T) {
	cg := NewCallGraph("/project", "s4")

	content := `class Service:
    def run(self, items):
        return sorted(items, key=lambda x: x.priority)
`
	buildPythonNodes(cg, "/project/svc.py", content, nil)

	method := cg.GetNode("/project/svc.py:Service.run")
	if method == nil {
		t.Fatal("expected Service.run method node")
	}
	closure := findPythonClosureNode(cg, "/project/svc.py", "Service.run")
	if closure == nil {
		t.Fatal("expected lambda closure under Service.run")
	}
	if !strings.HasPrefix(closure.Name, "Service.run.lambda@") {
		t.Errorf("closure name = %q, want prefix Service.run.lambda@", closure.Name)
	}
}

// TestBuildPythonRescanUnchangedPreservesClosures verifies that a
// rescan of unchanged content keeps closure nodes alive and doesn't
// duplicate their edges.
func TestBuildPythonRescanUnchangedPreservesClosures(t *testing.T) {
	content := `def f():
    return lambda x: g(x)

def g(x):
    return x
`
	cg := NewCallGraph("/project", "s1")
	buildPythonNodes(cg, "/project/r.py", content, nil)
	c1 := findPythonClosureNode(cg, "/project/r.py", "f")
	if c1 == nil {
		t.Fatal("expected lambda closure on first scan")
	}
	calls1 := len(c1.Calls)
	calledBy1 := len(c1.CalledBy)

	buildPythonNodes(cg, "/project/r.py", content, nil)
	c2 := findPythonClosureNode(cg, "/project/r.py", "f")
	if c2 == nil {
		t.Fatal("expected lambda closure after rescan")
	}
	if c2.ID != c1.ID {
		t.Errorf("closure ID changed on rescan: %q -> %q", c1.ID, c2.ID)
	}
	if len(c2.Calls) != calls1 {
		t.Errorf("closure.Calls length changed on rescan: %d -> %d (edges duplicated?)", calls1, len(c2.Calls))
	}
	if len(c2.CalledBy) != calledBy1 {
		t.Errorf("closure.CalledBy length changed on rescan: %d -> %d (edges duplicated?)", calledBy1, len(c2.CalledBy))
	}
}

// TestExtractPythonClosureSignatures verifies the Python extractor
// emits FuncSignatures for lambdas and nested defs with IsClosure set,
// using the same canonical names as the builder.
func TestExtractPythonClosureSignatures(t *testing.T) {
	src := `def outer(app):
    app.add_url_rule('/x', view_func=lambda: 1)
    def inner(req):
        return req
    return inner
`
	ex := GetExtractor(rules.LangPython)
	if ex == nil {
		t.Fatal("Python extractor not registered")
	}
	sigs := ex.ExtractFunctions(&ExtractContext{
		FilePath: "/app/v.py",
		Content:  []byte(src),
		Language: rules.LangPython,
	})

	var lambdaSig, innerSig, outerSig *FuncSignature
	for i := range sigs {
		s := &sigs[i]
		switch {
		case s.Name == "outer":
			outerSig = s
		case strings.Contains(s.Name, ".lambda@"):
			lambdaSig = s
		case strings.Contains(s.Name, ".inner@"):
			innerSig = s
		}
	}
	if outerSig == nil {
		t.Fatal("missing outer signature")
	}
	if outerSig.IsClosure {
		t.Errorf("outer.IsClosure = true, want false (regular def)")
	}
	if lambdaSig == nil {
		t.Fatalf("missing lambda signature; sigs=%v", sigNames(sigs))
	}
	if !lambdaSig.IsClosure {
		t.Errorf("lambda.IsClosure = false, want true")
	}
	if !strings.HasPrefix(lambdaSig.Name, "outer.lambda@") {
		t.Errorf("lambda name = %q, want prefix outer.lambda@", lambdaSig.Name)
	}
	if innerSig == nil {
		t.Fatalf("missing nested-def signature; sigs=%v", sigNames(sigs))
	}
	if !innerSig.IsClosure {
		t.Errorf("inner.IsClosure = false, want true")
	}
	if !strings.HasPrefix(innerSig.Name, "outer.inner@") {
		t.Errorf("inner name = %q, want prefix outer.inner@", innerSig.Name)
	}
	// Inner has param `req` — make sure params are populated even on
	// closures (callers use this for typed-summary propagation).
	if len(innerSig.Params) != 1 || innerSig.Params[0].Name != "req" {
		t.Errorf("inner.Params = %v, want one param named req", innerSig.Params)
	}
}

// TestExtractPythonLambdaParams covers param extraction for lambdas —
// including `*args` / `**kwargs` which the lambda_parameters grammar
// emits as list_splat_pattern / dictionary_splat_pattern.
func TestExtractPythonLambdaParams(t *testing.T) {
	src := `def outer():
    f = lambda x, *args, **kw: x
    return f
`
	ex := GetExtractor(rules.LangPython)
	sigs := ex.ExtractFunctions(&ExtractContext{
		FilePath: "/app/p.py",
		Content:  []byte(src),
		Language: rules.LangPython,
	})
	var lambdaSig *FuncSignature
	for i := range sigs {
		if strings.Contains(sigs[i].Name, ".lambda@") {
			lambdaSig = &sigs[i]
			break
		}
	}
	if lambdaSig == nil {
		t.Fatalf("missing lambda signature; sigs=%v", sigNames(sigs))
	}
	if len(lambdaSig.Params) != 3 {
		t.Errorf("lambda.Params length = %d, want 3 (x, *args, **kw): %+v", len(lambdaSig.Params), lambdaSig.Params)
	}
}

// containsRawCall returns true when n.RawCalls contains call.
func containsRawCall(n *FuncNode, call string) bool {
	if n == nil {
		return false
	}
	for _, c := range n.RawCalls {
		if c == call {
			return true
		}
	}
	return false
}

// findPythonClosureNode returns the (single) closure node anchored
// directly under enclosingName in filePath, or nil if none / multiple.
// "Directly under" means the closure's name starts with
// "<enclosingName>." and contains "@" — i.e. it's a child closure but
// not a grandchild. Use NodesInFile manually for deeper tests.
func findPythonClosureNode(cg *CallGraph, filePath, enclosingName string) *FuncNode {
	prefix := enclosingName + "."
	var found *FuncNode
	for _, n := range cg.NodesInFile(filePath) {
		if !strings.HasPrefix(n.Name, prefix) {
			continue
		}
		// Require exactly one "@" anchor at the same depth as the
		// direct child (so "outer.middle@10:4" matches but
		// "outer.middle@10:4.lambda@12:8" does not when we're looking
		// for direct children of `outer`).
		rest := strings.TrimPrefix(n.Name, prefix)
		if !strings.Contains(rest, "@") {
			continue
		}
		// Direct child: rest must NOT contain another "." before "@".
		at := strings.IndexByte(rest, '@')
		if strings.IndexByte(rest[:at], '.') >= 0 {
			continue
		}
		if found != nil {
			return nil
		}
		found = n
	}
	return found
}

func containsString(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

func sigNames(sigs []FuncSignature) []string {
	out := make([]string, len(sigs))
	for i, s := range sigs {
		out[i] = s.Name
	}
	return out
}
