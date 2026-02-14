package graph_test

import (
	"testing"

	"github.com/turenio/gtss/internal/graph"
	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"
)

// ---------------------------------------------------------------------------
// NewCallGraph and basic node operations
// ---------------------------------------------------------------------------

func TestNewCallGraph(t *testing.T) {
	cg := graph.NewCallGraph("/project", "session-1")

	if cg.ProjectRoot != "/project" {
		t.Errorf("ProjectRoot = %q, want %q", cg.ProjectRoot, "/project")
	}
	if cg.SessionID != "session-1" {
		t.Errorf("SessionID = %q, want %q", cg.SessionID, "session-1")
	}
	if cg.Version != 1 {
		t.Errorf("Version = %d, want 1", cg.Version)
	}
	if len(cg.Nodes) != 0 {
		t.Errorf("Nodes should be empty, got %d", len(cg.Nodes))
	}
}

func TestAddAndGetNode(t *testing.T) {
	cg := graph.NewCallGraph("/project", "s1")

	node := &graph.FuncNode{
		ID:       "file.go:Handler",
		FilePath: "/project/file.go",
		Name:     "Handler",
		Language: rules.LangGo,
	}
	cg.AddNode(node)

	got := cg.GetNode("file.go:Handler")
	if got == nil {
		t.Fatal("GetNode returned nil for added node")
	}
	if got.Name != "Handler" {
		t.Errorf("node.Name = %q, want %q", got.Name, "Handler")
	}
}

func TestGetNodeNonExistent(t *testing.T) {
	cg := graph.NewCallGraph("/project", "s1")
	if got := cg.GetNode("nonexistent"); got != nil {
		t.Errorf("expected nil for non-existent node, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// FuncID
// ---------------------------------------------------------------------------

func TestFuncID(t *testing.T) {
	id := graph.FuncID("/app/handler.go", "ServeHTTP")
	if id != "/app/handler.go:ServeHTTP" {
		t.Errorf("FuncID = %q, want %q", id, "/app/handler.go:ServeHTTP")
	}
}

// ---------------------------------------------------------------------------
// ContentHash
// ---------------------------------------------------------------------------

func TestContentHash(t *testing.T) {
	h1 := graph.ContentHash("func foo() {}")
	h2 := graph.ContentHash("func bar() {}")
	h3 := graph.ContentHash("func foo() {}")

	if h1 == h2 {
		t.Error("different content should produce different hashes")
	}
	if h1 != h3 {
		t.Error("same content should produce same hash")
	}
	if len(h1) != 16 {
		t.Errorf("hash length = %d, want 16 hex chars", len(h1))
	}
}

// ---------------------------------------------------------------------------
// Edge operations
// ---------------------------------------------------------------------------

func TestAddEdge(t *testing.T) {
	cg := graph.NewCallGraph("/project", "s1")

	caller := &graph.FuncNode{ID: "f:A", FilePath: "f", Name: "A"}
	callee := &graph.FuncNode{ID: "f:B", FilePath: "f", Name: "B"}
	cg.AddNode(caller)
	cg.AddNode(callee)

	cg.AddEdge("f:A", "f:B")

	gotCaller := cg.GetNode("f:A")
	if len(gotCaller.Calls) != 1 || gotCaller.Calls[0] != "f:B" {
		t.Errorf("caller.Calls = %v, want [f:B]", gotCaller.Calls)
	}
	gotCallee := cg.GetNode("f:B")
	if len(gotCallee.CalledBy) != 1 || gotCallee.CalledBy[0] != "f:A" {
		t.Errorf("callee.CalledBy = %v, want [f:A]", gotCallee.CalledBy)
	}
}

func TestAddEdgeDuplicate(t *testing.T) {
	cg := graph.NewCallGraph("/project", "s1")

	caller := &graph.FuncNode{ID: "f:A", FilePath: "f", Name: "A"}
	callee := &graph.FuncNode{ID: "f:B", FilePath: "f", Name: "B"}
	cg.AddNode(caller)
	cg.AddNode(callee)

	cg.AddEdge("f:A", "f:B")
	cg.AddEdge("f:A", "f:B") // duplicate

	gotCaller := cg.GetNode("f:A")
	if len(gotCaller.Calls) != 1 {
		t.Errorf("duplicate edge should not create multiple entries, got %d", len(gotCaller.Calls))
	}
}

func TestAddEdgeNilNodes(t *testing.T) {
	cg := graph.NewCallGraph("/project", "s1")
	// Should not panic when nodes don't exist.
	cg.AddEdge("nonexistent:A", "nonexistent:B")
}

func TestRemoveEdge(t *testing.T) {
	cg := graph.NewCallGraph("/project", "s1")

	a := &graph.FuncNode{ID: "f:A", FilePath: "f", Name: "A"}
	b := &graph.FuncNode{ID: "f:B", FilePath: "f", Name: "B"}
	cg.AddNode(a)
	cg.AddNode(b)
	cg.AddEdge("f:A", "f:B")

	cg.RemoveEdge("f:A", "f:B")

	if len(cg.GetNode("f:A").Calls) != 0 {
		t.Error("after RemoveEdge, caller.Calls should be empty")
	}
	if len(cg.GetNode("f:B").CalledBy) != 0 {
		t.Error("after RemoveEdge, callee.CalledBy should be empty")
	}
}

// ---------------------------------------------------------------------------
// GetCallers / GetCallees
// ---------------------------------------------------------------------------

func TestGetCallers(t *testing.T) {
	cg := graph.NewCallGraph("/project", "s1")

	a := &graph.FuncNode{ID: "f:A", FilePath: "f", Name: "A"}
	b := &graph.FuncNode{ID: "f:B", FilePath: "f", Name: "B"}
	c := &graph.FuncNode{ID: "f:C", FilePath: "f", Name: "C"}
	cg.AddNode(a)
	cg.AddNode(b)
	cg.AddNode(c)

	cg.AddEdge("f:A", "f:C")
	cg.AddEdge("f:B", "f:C")

	callers := cg.GetCallers("f:C")
	if len(callers) != 2 {
		t.Errorf("GetCallers returned %d, want 2", len(callers))
	}
}

func TestGetCallersNonExistent(t *testing.T) {
	cg := graph.NewCallGraph("/project", "s1")
	callers := cg.GetCallers("nonexistent")
	if callers != nil {
		t.Errorf("GetCallers for non-existent = %v, want nil", callers)
	}
}

func TestGetCallees(t *testing.T) {
	cg := graph.NewCallGraph("/project", "s1")

	a := &graph.FuncNode{ID: "f:A", FilePath: "f", Name: "A"}
	b := &graph.FuncNode{ID: "f:B", FilePath: "f", Name: "B"}
	c := &graph.FuncNode{ID: "f:C", FilePath: "f", Name: "C"}
	cg.AddNode(a)
	cg.AddNode(b)
	cg.AddNode(c)

	cg.AddEdge("f:A", "f:B")
	cg.AddEdge("f:A", "f:C")

	callees := cg.GetCallees("f:A")
	if len(callees) != 2 {
		t.Errorf("GetCallees returned %d, want 2", len(callees))
	}
}

// ---------------------------------------------------------------------------
// GetTransitiveCallers
// ---------------------------------------------------------------------------

func TestGetTransitiveCallers(t *testing.T) {
	cg := graph.NewCallGraph("/project", "s1")

	// Build chain: A -> B -> C -> D
	a := &graph.FuncNode{ID: "f:A", FilePath: "f", Name: "A"}
	b := &graph.FuncNode{ID: "f:B", FilePath: "f", Name: "B"}
	c := &graph.FuncNode{ID: "f:C", FilePath: "f", Name: "C"}
	d := &graph.FuncNode{ID: "f:D", FilePath: "f", Name: "D"}
	cg.AddNode(a)
	cg.AddNode(b)
	cg.AddNode(c)
	cg.AddNode(d)

	cg.AddEdge("f:A", "f:B")
	cg.AddEdge("f:B", "f:C")
	cg.AddEdge("f:C", "f:D")

	// Transitive callers of D (walking up): C, B, A
	callers := cg.GetTransitiveCallers("f:D", 10)
	if len(callers) != 3 {
		t.Errorf("GetTransitiveCallers returned %d nodes, want 3", len(callers))
	}
}

func TestGetTransitiveCallersMaxDepth(t *testing.T) {
	cg := graph.NewCallGraph("/project", "s1")

	a := &graph.FuncNode{ID: "f:A", FilePath: "f", Name: "A"}
	b := &graph.FuncNode{ID: "f:B", FilePath: "f", Name: "B"}
	c := &graph.FuncNode{ID: "f:C", FilePath: "f", Name: "C"}
	cg.AddNode(a)
	cg.AddNode(b)
	cg.AddNode(c)

	cg.AddEdge("f:A", "f:B")
	cg.AddEdge("f:B", "f:C")

	// Max depth of 1: only direct callers of C => B
	callers := cg.GetTransitiveCallers("f:C", 1)
	if len(callers) != 1 {
		t.Errorf("GetTransitiveCallers(maxDepth=1) returned %d, want 1", len(callers))
	}
}

// ---------------------------------------------------------------------------
// NodesInFile
// ---------------------------------------------------------------------------

func TestNodesInFile(t *testing.T) {
	cg := graph.NewCallGraph("/project", "s1")

	cg.AddNode(&graph.FuncNode{ID: "a.go:Foo", FilePath: "/project/a.go", Name: "Foo"})
	cg.AddNode(&graph.FuncNode{ID: "a.go:Bar", FilePath: "/project/a.go", Name: "Bar"})
	cg.AddNode(&graph.FuncNode{ID: "b.go:Baz", FilePath: "/project/b.go", Name: "Baz"})

	nodes := cg.NodesInFile("/project/a.go")
	if len(nodes) != 2 {
		t.Errorf("NodesInFile returned %d, want 2", len(nodes))
	}
}

// ---------------------------------------------------------------------------
// RemoveFile
// ---------------------------------------------------------------------------

func TestRemoveFile(t *testing.T) {
	cg := graph.NewCallGraph("/project", "s1")

	a := &graph.FuncNode{ID: "a.go:Foo", FilePath: "/project/a.go", Name: "Foo"}
	b := &graph.FuncNode{ID: "b.go:Bar", FilePath: "/project/b.go", Name: "Bar"}
	cg.AddNode(a)
	cg.AddNode(b)
	cg.AddEdge("b.go:Bar", "a.go:Foo")

	cg.RemoveFile("/project/a.go")

	if cg.GetNode("a.go:Foo") != nil {
		t.Error("expected node a.go:Foo to be removed")
	}
	if len(cg.GetNode("b.go:Bar").Calls) != 0 {
		t.Error("expected Bar's call edges to Foo to be cleaned up")
	}
}

// ---------------------------------------------------------------------------
// SignatureChanged
// ---------------------------------------------------------------------------

func TestSignatureChangedDetectsChanges(t *testing.T) {
	old := graph.TaintSignature{IsPure: true}
	new := graph.TaintSignature{IsPure: false}
	if !graph.SignatureChanged(old, new) {
		t.Error("expected SignatureChanged to detect IsPure change")
	}
}

func TestSignatureChangedSameSignatures(t *testing.T) {
	sig := graph.TaintSignature{
		TaintedParams:  map[int][]taint.SourceCategory{0: {taint.SrcUserInput}},
		TaintedReturns: map[int][]taint.SourceCategory{0: {taint.SrcUserInput}},
		IsPure:         false,
	}
	if graph.SignatureChanged(sig, sig) {
		t.Error("same signatures should not be flagged as changed")
	}
}

func TestSignatureChangedParamCountDiffers(t *testing.T) {
	old := graph.TaintSignature{
		TaintedParams: map[int][]taint.SourceCategory{0: {taint.SrcUserInput}},
	}
	new := graph.TaintSignature{
		TaintedParams: map[int][]taint.SourceCategory{},
	}
	if !graph.SignatureChanged(old, new) {
		t.Error("expected change when tainted param counts differ")
	}
}

func TestSignatureChangedSinkCountDiffers(t *testing.T) {
	old := graph.TaintSignature{}
	new := graph.TaintSignature{
		SinkCalls: []graph.SinkRef{{SinkCategory: taint.SnkSQLQuery}},
	}
	if !graph.SignatureChanged(old, new) {
		t.Error("expected change when sink call counts differ")
	}
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

func TestStats(t *testing.T) {
	cg := graph.NewCallGraph("/project", "s1")

	a := &graph.FuncNode{
		ID: "a.go:Foo", FilePath: "/project/a.go", Name: "Foo",
		TaintSig: graph.TaintSignature{
			TaintedParams: map[int][]taint.SourceCategory{0: {taint.SrcUserInput}},
		},
	}
	b := &graph.FuncNode{ID: "b.go:Bar", FilePath: "/project/b.go", Name: "Bar"}
	cg.AddNode(a)
	cg.AddNode(b)
	cg.AddEdge("a.go:Foo", "b.go:Bar")

	stats := cg.Stats()
	if stats.TotalFunctions != 2 {
		t.Errorf("TotalFunctions = %d, want 2", stats.TotalFunctions)
	}
	if stats.TotalEdges != 1 {
		t.Errorf("TotalEdges = %d, want 1", stats.TotalEdges)
	}
	if stats.FilesTracked != 2 {
		t.Errorf("FilesTracked = %d, want 2", stats.FilesTracked)
	}
	if stats.TaintedFuncs != 1 {
		t.Errorf("TaintedFuncs = %d, want 1", stats.TaintedFuncs)
	}
}
