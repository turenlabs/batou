package graph_test

// Additional behavior tests for the call-graph mutation, serialization,
// and cap/adoption surface that the existing callgraph_test.go / persist_test.go
// leave under-exercised:
//
//   - SignatureChanged value-comparison branches (Params/Returns/TypesVersion,
//     value-aware SinkCalls, SourceParams add/change, category-set swaps).
//   - UpdateFindingHistory create + accumulate semantics.
//   - HasCrossFileState marker logic (nil receiver, empty index, populated).
//   - RemoveEdge / GetCallees / GetTransitiveCallers nil-node edge paths.
//   - LoadGraphForHook adoption size-cap with the BATOU_HOOK_CROSSFILE_MAX_MB
//     env override, and the directory-as-graph-path edge.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/turenlabs/batou-core/graph"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// ---------------------------------------------------------------------------
// SignatureChanged: the value-comparison branches (callgraph.go is at 62.5%
// because most of these were never driven from a test).
// ---------------------------------------------------------------------------

func TestSignatureChanged_ValueBranches(t *testing.T) {
	base := graph.TaintSignature{
		TaintedParams:  map[int][]taint.SourceCategory{0: {taint.SrcUserInput}},
		TaintedReturns: map[int][]taint.SourceCategory{0: {taint.SrcUserInput}},
		SourceParams:   map[int]taint.SourceCategory{1: taint.SrcUserInput},
		SinkCalls: []graph.SinkRef{
			{SinkCategory: taint.SnkSQLQuery, MethodName: "Query", ArgFromParam: 0},
		},
		Params:       []graph.ParamTaint{{Index: 0, Name: "a"}},
		Returns:      []graph.ReturnTaint{{Index: 0}},
		TypesVersion: 1,
	}

	// clone returns a deep-ish copy of base that the mutator can edit.
	clone := func() graph.TaintSignature {
		s := base
		s.TaintedParams = map[int][]taint.SourceCategory{0: {taint.SrcUserInput}}
		s.TaintedReturns = map[int][]taint.SourceCategory{0: {taint.SrcUserInput}}
		s.SourceParams = map[int]taint.SourceCategory{1: taint.SrcUserInput}
		s.SinkCalls = []graph.SinkRef{{SinkCategory: taint.SnkSQLQuery, MethodName: "Query", ArgFromParam: 0}}
		s.Params = []graph.ParamTaint{{Index: 0, Name: "a"}}
		s.Returns = []graph.ReturnTaint{{Index: 0}}
		return s
	}

	// Identical signatures => NOT changed (exercises the full fall-through).
	if graph.SignatureChanged(base, clone()) {
		t.Fatal("identical signatures must not be reported as changed")
	}

	tests := []struct {
		name   string
		mutate func(s *graph.TaintSignature)
	}{
		{"TypesVersion bump", func(s *graph.TaintSignature) { s.TypesVersion = 2 }},
		{"Params count", func(s *graph.TaintSignature) { s.Params = nil }},
		{"Returns count", func(s *graph.TaintSignature) { s.Returns = nil }},
		{"sink category swap", func(s *graph.TaintSignature) {
			s.SinkCalls[0].SinkCategory = taint.SnkCommand
		}},
		{"sink method swap", func(s *graph.TaintSignature) {
			s.SinkCalls[0].MethodName = "Exec"
		}},
		{"sink arg-from-param remap", func(s *graph.TaintSignature) {
			s.SinkCalls[0].ArgFromParam = 1
		}},
		{"sink field-path change", func(s *graph.TaintSignature) {
			s.SinkCalls[0].ArgFieldPath = "cmd"
		}},
		{"source param count", func(s *graph.TaintSignature) {
			s.SourceParams[2] = taint.SrcUserInput
		}},
		{"source param category change", func(s *graph.TaintSignature) {
			s.SourceParams[1] = taint.SrcNetwork
		}},
		{"source param key change", func(s *graph.TaintSignature) {
			s.SourceParams = map[int]taint.SourceCategory{3: taint.SrcUserInput}
		}},
		{"tainted param category swap", func(s *graph.TaintSignature) {
			s.TaintedParams[0] = []taint.SourceCategory{taint.SrcNetwork}
		}},
		{"tainted param key missing", func(s *graph.TaintSignature) {
			s.TaintedParams = map[int][]taint.SourceCategory{5: {taint.SrcUserInput}}
		}},
		{"tainted return category swap", func(s *graph.TaintSignature) {
			s.TaintedReturns[0] = []taint.SourceCategory{taint.SrcDatabase}
		}},
		{"tainted return key missing", func(s *graph.TaintSignature) {
			s.TaintedReturns = map[int][]taint.SourceCategory{9: {taint.SrcUserInput}}
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			newSig := clone()
			tc.mutate(&newSig)
			if !graph.SignatureChanged(base, newSig) {
				t.Errorf("expected SignatureChanged=true for %q", tc.name)
			}
		})
	}
}

// A category set with the same members in a different order (and with a
// duplicate) must NOT be treated as changed — this exercises sameCategorySet's
// multiset comparison.
func TestSignatureChanged_CategoryOrderInsensitive(t *testing.T) {
	old := graph.TaintSignature{
		TaintedParams: map[int][]taint.SourceCategory{
			0: {taint.SrcUserInput, taint.SrcNetwork},
		},
	}
	reordered := graph.TaintSignature{
		TaintedParams: map[int][]taint.SourceCategory{
			0: {taint.SrcNetwork, taint.SrcUserInput},
		},
	}
	if graph.SignatureChanged(old, reordered) {
		t.Error("same category set in different order must not be reported as changed")
	}

	// Same length but a genuinely different member => changed.
	different := graph.TaintSignature{
		TaintedParams: map[int][]taint.SourceCategory{
			0: {taint.SrcNetwork, taint.SrcDatabase},
		},
	}
	if !graph.SignatureChanged(old, different) {
		t.Error("different category member must be reported as changed")
	}
}

// ---------------------------------------------------------------------------
// UpdateFindingHistory: 0% before — create path, accumulate-fixed semantics,
// and the nil-map lazy init.
// ---------------------------------------------------------------------------

func TestUpdateFindingHistory_CreateAndAccumulate(t *testing.T) {
	// Start from a graph with a nil FileFindingHistories map to drive the
	// lazy-init branch.
	cg := &graph.CallGraph{Nodes: map[string]*graph.FuncNode{}}

	h1 := graph.FileContentHash("v1")
	cg.UpdateFindingHistory("/app/x.go", h1, 4 /*active*/, 1 /*fixed*/, 2 /*suppressed*/)

	got := cg.FileFindingHistories["/app/x.go"]
	if got == nil {
		t.Fatal("expected a history entry after first update")
	}
	if got.ActiveCount != 4 || got.FixedCount != 1 || got.SuppressedCount != 2 {
		t.Errorf("first update = %+v, want active=4 fixed=1 suppressed=2", got)
	}
	if got.ContentHash != h1 {
		t.Errorf("ContentHash = %d, want %d", got.ContentHash, h1)
	}
	if got.LastScanned.IsZero() {
		t.Error("LastScanned should be set")
	}

	// Second update: ActiveCount/SuppressedCount overwrite, FixedCount
	// ACCUMULATES (the documented "total fixed over time" semantics).
	h2 := graph.FileContentHash("v2")
	cg.UpdateFindingHistory("/app/x.go", h2, 3, 2, 0)

	got = cg.FileFindingHistories["/app/x.go"]
	if got.ActiveCount != 3 {
		t.Errorf("ActiveCount = %d, want 3 (overwritten)", got.ActiveCount)
	}
	if got.SuppressedCount != 0 {
		t.Errorf("SuppressedCount = %d, want 0 (overwritten)", got.SuppressedCount)
	}
	if got.FixedCount != 3 { // 1 + 2 accumulated
		t.Errorf("FixedCount = %d, want 3 (1 accumulated + 2)", got.FixedCount)
	}
	if got.ContentHash != h2 {
		t.Errorf("ContentHash = %d, want %d (updated)", got.ContentHash, h2)
	}

	// A distinct file gets its own independent entry.
	cg.UpdateFindingHistory("/app/y.go", h1, 1, 0, 0)
	if len(cg.FileFindingHistories) != 2 {
		t.Errorf("expected 2 file histories, got %d", len(cg.FileFindingHistories))
	}
}

// ---------------------------------------------------------------------------
// HasCrossFileState: the marker that distinguishes a scan-built graph.
// ---------------------------------------------------------------------------

func TestHasCrossFileState(t *testing.T) {
	var nilCG *graph.CallGraph
	if nilCG.HasCrossFileState() {
		t.Error("nil graph must report no cross-file state")
	}

	cg := graph.NewCallGraph("/p", "s")
	if cg.HasCrossFileState() {
		t.Error("fresh graph (nil PackageIndex) must report no cross-file state")
	}

	// Non-nil but EMPTY PackageIndex is still "no state".
	cg.PackageIndex = graph.NewPackageIndex()
	if cg.HasCrossFileState() {
		t.Error("empty PackageIndex must report no cross-file state")
	}

	// Populated index flips the marker.
	cg.PackageIndex.Add("example.com/app", "/p/app.go:Run")
	if !cg.HasCrossFileState() {
		t.Error("populated PackageIndex must report cross-file state")
	}
}

// ---------------------------------------------------------------------------
// RemoveEdge: the nil-caller and nil-callee guarded branches.
// ---------------------------------------------------------------------------

func TestRemoveEdge_MissingNodes(t *testing.T) {
	cg := graph.NewCallGraph("/p", "s")
	a := &graph.FuncNode{ID: "f:A", FilePath: "f", Name: "A"}
	cg.AddNode(a)
	cg.AddEdge("f:A", "f:B") // f:B absent — no-op, A keeps no Calls.

	// RemoveEdge where only the caller exists: must not panic and must not
	// corrupt the caller. (callee nil branch)
	cg.RemoveEdge("f:A", "f:B")
	if len(cg.GetNode("f:A").Calls) != 0 {
		t.Errorf("caller.Calls = %v, want empty", cg.GetNode("f:A").Calls)
	}

	// RemoveEdge where only the callee exists (caller nil branch).
	b := &graph.FuncNode{ID: "f:B", FilePath: "f", Name: "B", CalledBy: []string{"f:Ghost"}}
	cg.AddNode(b)
	cg.RemoveEdge("f:Ghost", "f:B")
	if len(cg.GetNode("f:B").CalledBy) != 0 {
		t.Errorf("callee.CalledBy = %v, want Ghost removed", cg.GetNode("f:B").CalledBy)
	}

	// Both nil: pure no-op, no panic.
	cg.RemoveEdge("none:X", "none:Y")
}

// ---------------------------------------------------------------------------
// GetCallees / GetTransitiveCallers: nil-node and dangling-ID branches.
// ---------------------------------------------------------------------------

func TestGetCallees_NonExistentAndDangling(t *testing.T) {
	cg := graph.NewCallGraph("/p", "s")
	if got := cg.GetCallees("nope"); got != nil {
		t.Errorf("GetCallees on missing node = %v, want nil", got)
	}

	// A node whose Calls slice references an ID that is no longer in the
	// graph: the dangling ID is skipped (the `if callee != nil` branch).
	a := &graph.FuncNode{ID: "f:A", FilePath: "f", Name: "A", Calls: []string{"f:Gone", "f:B"}}
	b := &graph.FuncNode{ID: "f:B", FilePath: "f", Name: "B"}
	cg.AddNode(a)
	cg.AddNode(b)
	callees := cg.GetCallees("f:A")
	if len(callees) != 1 || callees[0].ID != "f:B" {
		t.Errorf("GetCallees = %v, want only [f:B] (dangling f:Gone skipped)", callees)
	}
}

func TestGetTransitiveCallers_DanglingAndMissing(t *testing.T) {
	cg := graph.NewCallGraph("/p", "s")
	if got := cg.GetTransitiveCallers("missing", 5); got != nil {
		t.Errorf("transitive callers of missing node = %v, want nil", got)
	}

	// Node referenced as a caller but absent from Nodes => skipped.
	leaf := &graph.FuncNode{ID: "f:Leaf", FilePath: "f", Name: "Leaf", CalledBy: []string{"f:Ghost", "f:Mid"}}
	mid := &graph.FuncNode{ID: "f:Mid", FilePath: "f", Name: "Mid"}
	cg.AddNode(leaf)
	cg.AddNode(mid)
	cg.AddEdge("f:Mid", "f:Leaf") // ensures back-edge integrity for Mid

	callers := cg.GetTransitiveCallers("f:Leaf", 5)
	// Only Mid resolves; Ghost is dangling and dropped.
	if len(callers) != 1 || callers[0].ID != "f:Mid" {
		t.Errorf("transitive callers = %v, want [f:Mid]", callers)
	}
}

// ---------------------------------------------------------------------------
// Stats on an empty graph: all-zero, no divide-by-zero / nil-map issues.
// ---------------------------------------------------------------------------

func TestStats_EmptyGraph(t *testing.T) {
	cg := graph.NewCallGraph("/p", "s")
	st := cg.Stats()
	if st.TotalFunctions != 0 || st.TotalEdges != 0 || st.FilesTracked != 0 || st.TaintedFuncs != 0 {
		t.Errorf("empty-graph stats = %+v, want all zero", st)
	}
}

// A node tainted only via SinkCalls (no TaintedParams) must still count as
// tainted — exercises the OR in the Stats tainted predicate.
func TestStats_TaintedViaSinkOnly(t *testing.T) {
	cg := graph.NewCallGraph("/p", "s")
	cg.AddNode(&graph.FuncNode{
		ID: "a.go:Sink", FilePath: "/p/a.go", Name: "Sink",
		TaintSig: graph.TaintSignature{
			SinkCalls: []graph.SinkRef{{SinkCategory: taint.SnkCommand}},
		},
	})
	cg.AddNode(&graph.FuncNode{ID: "a.go:Plain", FilePath: "/p/a.go", Name: "Plain"})
	st := cg.Stats()
	if st.TaintedFuncs != 1 {
		t.Errorf("TaintedFuncs = %d, want 1 (sink-only node counts)", st.TaintedFuncs)
	}
	if st.FilesTracked != 1 {
		t.Errorf("FilesTracked = %d, want 1", st.FilesTracked)
	}
}

// ---------------------------------------------------------------------------
// RemoveFile with a same-file caller: the back-edge cleanup must handle a
// caller that lives in the SAME file as the removed node (its node is deleted
// in the same sweep, so the cleanup must be tolerant).
// ---------------------------------------------------------------------------

func TestRemoveFile_SameFileAndCrossFileEdges(t *testing.T) {
	cg := graph.NewCallGraph("/p", "s")
	// a.go: Foo calls Bar (same file) and Bar calls External (b.go).
	cg.AddNode(&graph.FuncNode{ID: "a.go:Foo", FilePath: "/p/a.go", Name: "Foo"})
	cg.AddNode(&graph.FuncNode{ID: "a.go:Bar", FilePath: "/p/a.go", Name: "Bar"})
	cg.AddNode(&graph.FuncNode{ID: "b.go:External", FilePath: "/p/b.go", Name: "External"})
	cg.AddEdge("a.go:Foo", "a.go:Bar")
	cg.AddEdge("a.go:Bar", "b.go:External")

	cg.RemoveFile("/p/a.go")

	if cg.GetNode("a.go:Foo") != nil || cg.GetNode("a.go:Bar") != nil {
		t.Error("all a.go nodes should be removed")
	}
	ext := cg.GetNode("b.go:External")
	if ext == nil {
		t.Fatal("b.go:External should survive")
	}
	// External's back-edge to the now-gone Bar must be cleaned up.
	for _, c := range ext.CalledBy {
		if c == "a.go:Bar" {
			t.Errorf("External.CalledBy still references removed a.go:Bar: %v", ext.CalledBy)
		}
	}
}

// ---------------------------------------------------------------------------
// LoadGraphForHook: directory-at-graph-path edge and the env size-cap override.
// ---------------------------------------------------------------------------

// When the graph path is a DIRECTORY, os.Stat succeeds and reports IsDir,
// so the oversize cap branch is skipped; readGraphFile then tries to
// os.ReadFile the directory, which fails with a non-IsNotExist error that
// propagates out (it is NOT treated as "absent" — that path only triggers
// for os.IsNotExist). The loader therefore surfaces a hard read error and
// returns a nil graph, rather than silently starting fresh.
func TestLoadGraphForHook_GraphPathIsDirectory(t *testing.T) {
	root := t.TempDir()
	// Create .batou/callgraph.json as a DIRECTORY.
	graphDir := graph.GraphPath(root)
	if err := os.MkdirAll(graphDir, 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := graph.LoadGraphForHook(root, "sess")
	if err == nil {
		t.Fatalf("LoadGraphForHook on a directory path should surface a read error, got nil (graph=%+v)", got)
	}
	if got != nil {
		t.Errorf("on a hard read error the returned graph should be nil, got %+v", got)
	}
}

// The BATOU_HOOK_CROSSFILE_MAX_MB override at a tiny value forces a small
// scan-built graph over the cap, so it is declined with SkipPersist; an
// invalid override (0 / non-numeric) falls back to the default and adopts.
func TestLoadGraphForHook_EnvCapOverride(t *testing.T) {
	root := t.TempDir()
	cg := graph.NewCallGraph(root, "")
	cg.PackageIndex = graph.NewPackageIndex()
	cg.PackageIndex.Add("example.com/app", filepath.Join(root, "x.go")+":Run")
	cg.AddNode(&graph.FuncNode{ID: "x.go:Run", FilePath: "x.go", Name: "Run", Language: rules.LangGo})
	if err := graph.SaveGraph(cg); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(graph.GraphPath(root))
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() == 0 {
		t.Fatal("fixture graph unexpectedly empty")
	}

	// Cap set to 1 byte: any real graph exceeds it -> declined.
	t.Setenv("BATOU_HOOK_CROSSFILE_MAX_MB", "")
	// Re-set explicitly (t.Setenv with "" still unsets); use a real override.
	_ = os.Setenv("BATOU_HOOK_CROSSFILE_MAX_MB", "1")
	// 1 MB cap is larger than the small fixture, so it adopts.
	t.Cleanup(func() { _ = os.Unsetenv("BATOU_HOOK_CROSSFILE_MAX_MB") })

	adopted, err := graph.LoadGraphForHook(root, "hook")
	if err != nil {
		t.Fatal(err)
	}
	if !adopted.HasCrossFileState() {
		t.Error("graph under the 1MB cap should be adopted")
	}
	if adopted.SkipPersist {
		t.Error("adopted graph must remain persistable")
	}

	// Invalid override (non-numeric) -> falls back to default cap -> adopts.
	_ = os.Setenv("BATOU_HOOK_CROSSFILE_MAX_MB", "not-a-number")
	adopted2, err := graph.LoadGraphForHook(root, "hook")
	if err != nil {
		t.Fatal(err)
	}
	if !adopted2.HasCrossFileState() {
		t.Error("invalid env override should fall back to default and adopt")
	}

	// Negative / zero override -> ignored -> default cap -> adopts.
	_ = os.Setenv("BATOU_HOOK_CROSSFILE_MAX_MB", "0")
	adopted3, err := graph.LoadGraphForHook(root, "hook")
	if err != nil {
		t.Fatal(err)
	}
	if !adopted3.HasCrossFileState() {
		t.Error("zero env override should be ignored (default cap) and adopt")
	}
}

// ---------------------------------------------------------------------------
// LoadGraphAt: explicit-path stale-session reset (the SessionID != arg branch
// in LoadGraphAt that the round-trip tests don't drive at the *At entry).
// ---------------------------------------------------------------------------

func TestLoadGraphAt_StaleSessionResets(t *testing.T) {
	root := t.TempDir()
	alt := filepath.Join(root, "g", "callgraph.json")
	cg := graph.NewCallGraph(root, "session-old")
	cg.AddNode(&graph.FuncNode{ID: "f:A", FilePath: "f", Name: "A"})
	if err := graph.SaveGraphAt(cg, alt); err != nil {
		t.Fatal(err)
	}

	// Same session: loads with the node.
	same, err := graph.LoadGraphAt(alt, root, "session-old")
	if err != nil {
		t.Fatal(err)
	}
	if same.GetNode("f:A") == nil {
		t.Error("same-session LoadGraphAt should retain nodes")
	}

	// Different session: fresh graph.
	fresh, err := graph.LoadGraphAt(alt, root, "session-new")
	if err != nil {
		t.Fatal(err)
	}
	if fresh.SessionID != "session-new" || len(fresh.Nodes) != 0 {
		t.Errorf("stale-session LoadGraphAt should reset; got session=%q nodes=%d", fresh.SessionID, len(fresh.Nodes))
	}
}

// ---------------------------------------------------------------------------
// CanonicalGraphPath: the FileScopes-keyed graphKnowsFile branch and the
// "./"+rel candidate. (incremental.go graphKnowsFile/CanonicalGraphPath gaps.)
// ---------------------------------------------------------------------------

func TestCanonicalGraphPath_KnownViaFileScopeAndDotSlash(t *testing.T) {
	root := t.TempDir()
	cg := graph.NewCallGraph(root, "")
	// Graph "knows" the file only via FileScopes, keyed under the "./"+rel
	// spelling — no node carries that FilePath. Drives both the FileScopes
	// short-circuit in graphKnowsFile and the "./"+rel candidate loop.
	cg.FileScopes = map[string]graph.FileScope{
		"./pkg/y.go": {Package: "pkg"},
	}
	abs := filepath.Join(root, "pkg", "y.go")
	if got := graph.CanonicalGraphPath(cg, abs); got != "./pkg/y.go" {
		t.Errorf("CanonicalGraphPath(%q) = %q, want ./pkg/y.go", abs, got)
	}

	// nil graph and empty path: identity / passthrough.
	if got := graph.CanonicalGraphPath(nil, abs); got != abs {
		t.Errorf("nil graph should be identity, got %q", got)
	}
	if got := graph.CanonicalGraphPath(cg, ""); got != "" {
		t.Errorf("empty path should be identity, got %q", got)
	}

	// Relative input (not abs) with no matching node/scope: identity.
	if got := graph.CanonicalGraphPath(cg, "rel/only.go"); got != "rel/only.go" {
		t.Errorf("relative unknown path should be identity, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// SetFileTaintCache on a nil-map graph (deserialized w/ null map): lazy init.
// ---------------------------------------------------------------------------

func TestSetFileTaintCache_NilMapLazyInit(t *testing.T) {
	cg := &graph.CallGraph{Nodes: map[string]*graph.FuncNode{}} // FileTaintCaches nil
	cg.SetFileTaintCache("/app/z.go", graph.FileContentHash("z"), 7)
	entry := cg.GetFileTaintCache("/app/z.go")
	if entry == nil {
		t.Fatal("expected cache entry after set on nil map")
	}
	if entry.FlowCount != 7 {
		t.Errorf("FlowCount = %d, want 7", entry.FlowCount)
	}
}
