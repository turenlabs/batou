package graph_test

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/graph"
	"github.com/turenlabs/batou-rules/rules"
)

// ---------------------------------------------------------------------------
// UpdateFile with Go source (uses go/ast)
// ---------------------------------------------------------------------------

func TestUpdateFileGoBasic(t *testing.T) {
	cg := graph.NewCallGraph("/project", "s1")

	content := `package main

func Foo() {
	Bar()
}

func Bar() {
	println("hello")
}
`

	updated := graph.UpdateFile(cg, "/project/main.go", content, rules.LangGo)

	if len(updated) != 2 {
		t.Errorf("UpdateFile returned %d updated IDs, want 2", len(updated))
	}

	foo := cg.GetNode("/project/main.go:Foo")
	if foo == nil {
		t.Fatal("expected Foo node to exist")
	}
	if foo.Package != "main" {
		t.Errorf("Foo.Package = %q, want %q", foo.Package, "main")
	}

	bar := cg.GetNode("/project/main.go:Bar")
	if bar == nil {
		t.Fatal("expected Bar node to exist")
	}

	// Foo should call Bar.
	if len(foo.Calls) != 1 || foo.Calls[0] != "/project/main.go:Bar" {
		t.Errorf("Foo.Calls = %v, want [/project/main.go:Bar]", foo.Calls)
	}
}

// TestUpdateFileGoLinkNameStub regression-tests against the panic that fired
// in graph.buildGoNodes when scanning files containing //go:linkname stubs
// (e.g. nats-server/internal/fastrand/fastrand.go), where FuncDecl.Body is nil.
func TestUpdateFileGoLinkNameStub(t *testing.T) {
	cg := graph.NewCallGraph("/project", "s1")

	content := `package fastrand

import _ "unsafe"

//go:linkname Uint32 runtime.fastrand
func Uint32() uint32

//go:linkname Uint32n runtime.fastrandn
func Uint32n(n uint32) uint32

func WithBody() uint32 {
	return Uint32()
}
`

	// Should not panic. Body-less stubs are skipped; the function with a
	// body still ends up in the graph.
	graph.UpdateFile(cg, "/project/fastrand.go", content, rules.LangGo)

	if cg.GetNode("/project/fastrand.go:Uint32") != nil {
		t.Error("body-less Uint32 stub should not be registered as a graph node")
	}
	if cg.GetNode("/project/fastrand.go:WithBody") == nil {
		t.Error("WithBody (with body) should be registered")
	}
}

func TestUpdateFileGoMethodReceiver(t *testing.T) {
	cg := graph.NewCallGraph("/project", "s1")

	content := `package main

type Server struct{}

func (s *Server) Handle() {
	s.process()
}

func (s *Server) process() {}
`

	graph.UpdateFile(cg, "/project/server.go", content, rules.LangGo)

	handle := cg.GetNode("/project/server.go:Server.Handle")
	if handle == nil {
		t.Fatal("expected Server.Handle node")
	}

	process := cg.GetNode("/project/server.go:Server.process")
	if process == nil {
		t.Fatal("expected Server.process node")
	}
}

func TestUpdateFileGoUnchangedContent(t *testing.T) {
	cg := graph.NewCallGraph("/project", "s1")

	content := `package main

func Foo() {}
`

	// First call creates the node.
	updated1 := graph.UpdateFile(cg, "/project/main.go", content, rules.LangGo)
	if len(updated1) != 1 {
		t.Fatalf("first UpdateFile should return 1, got %d", len(updated1))
	}

	// Second call with same content should detect no changes.
	updated2 := graph.UpdateFile(cg, "/project/main.go", content, rules.LangGo)
	if len(updated2) != 0 {
		t.Errorf("second UpdateFile with same content returned %d, want 0", len(updated2))
	}
}

func TestUpdateFileGoParseError(t *testing.T) {
	cg := graph.NewCallGraph("/project", "s1")

	// Invalid Go code.
	content := `package main
func { broken syntax
`

	updated := graph.UpdateFile(cg, "/project/bad.go", content, rules.LangGo)
	if updated != nil {
		t.Errorf("expected nil for parse error, got %v", updated)
	}
}

// ---------------------------------------------------------------------------
// UpdateFile with generic (non-Go) languages
// ---------------------------------------------------------------------------

func TestUpdateFilePython(t *testing.T) {
	cg := graph.NewCallGraph("/project", "s1")

	content := `def handler(request):
    data = request.args.get("q")
    return process(data)

def process(data):
    return data.strip()
`

	updated := graph.UpdateFile(cg, "/project/app.py", content, rules.LangPython)

	// Should detect at least the handler and process functions.
	if len(updated) == 0 {
		t.Error("expected at least one updated function for Python")
	}

	nodes := cg.NodesInFile("/project/app.py")
	if len(nodes) == 0 {
		t.Error("expected nodes in file after UpdateFile for Python")
	}
}

func TestUpdateFileJavaScript(t *testing.T) {
	cg := graph.NewCallGraph("/project", "s1")

	content := `function handleRequest(req, res) {
    const data = req.body;
    processData(data);
}

function processData(data) {
    return data.trim();
}
`

	updated := graph.UpdateFile(cg, "/project/app.js", content, rules.LangJavaScript)

	if len(updated) == 0 {
		t.Error("expected at least one updated function for JavaScript")
	}
}

// ---------------------------------------------------------------------------
// extractCalls (tested indirectly through UpdateFile)
// ---------------------------------------------------------------------------

func TestExtractCallsFiltersKeywords(t *testing.T) {
	cg := graph.NewCallGraph("/project", "s1")

	content := `function handler(req, res) {
    if (true) {
        for (let i = 0; i < 10; i++) {
            customFunc();
        }
    }
}
`

	graph.UpdateFile(cg, "/project/app.js", content, rules.LangJavaScript)

	handler := cg.GetNode("/project/app.js:handler")
	if handler == nil {
		t.Fatal("expected handler node")
	}

	// customFunc should be in calls but keywords (if, for, let) should not.
	for _, callID := range handler.Calls {
		node := cg.GetNode(callID)
		if node != nil {
			name := node.Name
			if name == "if" || name == "for" || name == "let" {
				t.Errorf("keyword %q should not appear as a call edge", name)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Closure (FuncLit) nodes — PR-S
// ---------------------------------------------------------------------------

// TestUpdateFileGoHTTPHandlerFactoryClosure covers the canonical Go HTTP
// handler factory pattern: `func HandleX(c *Controller) http.HandlerFunc {
// return func(w http.ResponseWriter, r *http.Request) { ... } }`. Before
// PR-S the closure's params and body calls were invisible to the call
// graph; this test pins the new behavior.
func TestUpdateFileGoHTTPHandlerFactoryClosure(t *testing.T) {
	cg := graph.NewCallGraph("/project", "s1")

	content := `package handler

import "net/http"

func HandleDiff(ctrl *Controller) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		render(ctrl, w, r)
	}
}

func render(c *Controller, w http.ResponseWriter, r *http.Request) {}
`

	graph.UpdateFile(cg, "/project/handler.go", content, rules.LangGo)

	// Outer FuncDecl node still exists with just its `ctrl` param.
	outer := cg.GetNode("/project/handler.go:HandleDiff")
	if outer == nil {
		t.Fatal("expected HandleDiff outer node")
	}

	// Closure FuncNode at the `return func(...)` site (line 6, column 9).
	// The exact column matches go/token.Position.Column for the FuncLit.
	closure := findClosureNode(t, cg, "/project/handler.go", "HandleDiff")
	if closure == nil {
		t.Fatal("expected one closure node under HandleDiff")
	}
	if !strings.HasPrefix(closure.Name, "HandleDiff.closure@") {
		t.Errorf("closure name = %q, want prefix %q", closure.Name, "HandleDiff.closure@")
	}
	if closure.FilePath != "/project/handler.go" {
		t.Errorf("closure FilePath = %q, want /project/handler.go", closure.FilePath)
	}
	if closure.Language != rules.LangGo {
		t.Errorf("closure Language = %q, want LangGo", closure.Language)
	}
	if closure.StartLine == 0 || closure.EndLine == 0 {
		t.Errorf("closure StartLine=%d EndLine=%d, want both > 0", closure.StartLine, closure.EndLine)
	}

	// Synthetic edge: outer.Calls includes the closure ID, closure.CalledBy
	// includes the outer ID.
	if !containsString(outer.Calls, closure.ID) {
		t.Errorf("outer.Calls = %v, want to include closure ID %q", outer.Calls, closure.ID)
	}
	if !containsString(closure.CalledBy, outer.ID) {
		t.Errorf("closure.CalledBy = %v, want to include outer ID %q", closure.CalledBy, outer.ID)
	}

	// Calls *inside* the closure body (render) are attributed to the
	// CLOSURE, not the outer function. This is the key behavioral change.
	renderID := "/project/handler.go:render"
	if containsString(outer.Calls, renderID) {
		t.Errorf("outer.Calls = %v, should NOT include render — that call is inside the closure body", outer.Calls)
	}
	if !containsString(closure.Calls, renderID) {
		t.Errorf("closure.Calls = %v, want to include render ID %q", closure.Calls, renderID)
	}
}

// TestUpdateFileGoNestedClosures verifies the stack-based attribution
// correctly handles closures-within-closures: each inner call goes to
// the innermost enclosing FuncLit, not to the outer FuncDecl.
func TestUpdateFileGoNestedClosures(t *testing.T) {
	cg := graph.NewCallGraph("/project", "s1")

	content := `package handler

func Outer() func() func() {
	return func() func() {
		return func() {
			inner()
		}
	}
}

func inner() {}
`

	graph.UpdateFile(cg, "/project/nested.go", content, rules.LangGo)

	// We expect three nodes for Outer + 2 nested closures (the outermost
	// FuncLit and the inner FuncLit).
	outer := cg.GetNode("/project/nested.go:Outer")
	if outer == nil {
		t.Fatal("expected Outer node")
	}
	innerID := "/project/nested.go:inner"

	// Outer.Calls must NOT include inner — that call is two levels deep
	// inside closures.
	if containsString(outer.Calls, innerID) {
		t.Errorf("Outer.Calls = %v, should NOT include inner (call is inside nested closure)", outer.Calls)
	}

	// Find the deepest closure node — it should be the only one with
	// `inner` in its Calls.
	var found *graph.FuncNode
	for _, n := range cg.NodesInFile("/project/nested.go") {
		if containsString(n.Calls, innerID) {
			if found != nil {
				t.Errorf("multiple nodes claim inner: %q and %q", found.ID, n.ID)
			}
			found = n
		}
	}
	if found == nil {
		t.Fatal("no node claims the call to inner")
	}
	if !strings.HasPrefix(found.Name, "Outer.closure@") {
		t.Errorf("innermost-claimer name = %q, want prefix Outer.closure@", found.Name)
	}
}

// TestUpdateFileGoClosureDeterministicID ensures the same source produces
// the same closure node ID across runs (required for the persisted call
// graph to round-trip stably).
func TestUpdateFileGoClosureDeterministicID(t *testing.T) {
	content := `package x

func F() func() {
	return func() { g() }
}

func g() {}
`

	cg1 := graph.NewCallGraph("/project", "s1")
	graph.UpdateFile(cg1, "/project/x.go", content, rules.LangGo)
	cg2 := graph.NewCallGraph("/project", "s2")
	graph.UpdateFile(cg2, "/project/x.go", content, rules.LangGo)

	closure1 := findClosureNode(t, cg1, "/project/x.go", "F")
	closure2 := findClosureNode(t, cg2, "/project/x.go", "F")
	if closure1 == nil || closure2 == nil {
		t.Fatal("expected closure nodes in both graphs")
	}
	if closure1.ID != closure2.ID {
		t.Errorf("closure IDs differ across runs: %q vs %q", closure1.ID, closure2.ID)
	}
}

// TestUpdateFileGoUnchangedContentPreservesClosureNodes verifies the
// outer-unchanged fast path still emits closure nodes (and doesn't
// duplicate edges on rescan).
func TestUpdateFileGoUnchangedContentPreservesClosureNodes(t *testing.T) {
	content := `package x

func F() func() {
	return func() { g() }
}

func g() {}
`
	cg := graph.NewCallGraph("/project", "s1")
	graph.UpdateFile(cg, "/project/x.go", content, rules.LangGo)
	closure1 := findClosureNode(t, cg, "/project/x.go", "F")
	if closure1 == nil {
		t.Fatal("expected closure node on first scan")
	}
	calls1Len := len(closure1.Calls)

	// Rescan the unchanged content. The closure node must still exist
	// and edges must not be duplicated.
	graph.UpdateFile(cg, "/project/x.go", content, rules.LangGo)
	closure2 := findClosureNode(t, cg, "/project/x.go", "F")
	if closure2 == nil {
		t.Fatal("expected closure node still present after rescan")
	}
	if closure2.ID != closure1.ID {
		t.Errorf("closure ID changed on rescan: %q -> %q", closure1.ID, closure2.ID)
	}
	if len(closure2.Calls) != calls1Len {
		t.Errorf("closure.Calls length changed on rescan: %d -> %d (edges duplicated?)", calls1Len, len(closure2.Calls))
	}
}

// findClosureNode returns the single closure node anchored under
// enclosingName in filePath, or nil if none exists. Fatals if multiple
// closures are found (use NodesInFile manually for nested-closure tests).
func findClosureNode(t *testing.T, cg *graph.CallGraph, filePath, enclosingName string) *graph.FuncNode {
	t.Helper()
	prefix := enclosingName + ".closure@"
	var found *graph.FuncNode
	for _, n := range cg.NodesInFile(filePath) {
		if strings.HasPrefix(n.Name, prefix) {
			if found != nil {
				return nil // multiple — caller should disambiguate
			}
			found = n
		}
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
