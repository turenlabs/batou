package graph

// Tests for the write-time hook cross-file lane primitives:
// LoadGraphForHook adoption policy, CallersOfFileFromOtherFiles,
// CanonicalGraphPath, ResolveCrossFileEdgesForFile, and
// WalkCrossFileTaintFlowsForCaller. Internal package tests because they
// exercise unexported plumbing (PackageIndex internals, resolver reuse).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// scanBuiltGraph builds a minimal graph that LOOKS scan-built: it has a
// populated PackageIndex (the cross-file state marker).
func scanBuiltGraph(root, sessionID string) *CallGraph {
	cg := NewCallGraph(root, sessionID)
	cg.PackageIndex = NewPackageIndex()
	cg.PackageIndex.Add("example.com/app/storage", filepath.Join(root, "storage", "db.go")+":RunQuery")
	return cg
}

func TestLoadGraphForHook_AdoptsScanBuiltGraphAcrossSessions(t *testing.T) {
	root := t.TempDir()
	cg := scanBuiltGraph(root, "") // batou scan persists with SessionID ""
	cg.AddNode(&FuncNode{ID: "f.go:F", FilePath: "f.go", Name: "F", Language: rules.LangGo})
	if err := SaveGraph(cg); err != nil {
		t.Fatal(err)
	}

	got, err := LoadGraphForHook(root, "hook-session-1")
	if err != nil {
		t.Fatal(err)
	}
	if !got.HasCrossFileState() {
		t.Fatalf("scan-built graph was not adopted: cross-file state missing")
	}
	if got.GetNode("f.go:F") == nil {
		t.Errorf("adopted graph lost its nodes")
	}
	// SessionID must be preserved so a later `batou scan` (which loads
	// with "") still warm-starts from this graph.
	if got.SessionID != "" {
		t.Errorf("adopted graph SessionID = %q, want preserved \"\"", got.SessionID)
	}
	if got.SkipPersist {
		t.Errorf("adopted graph must remain persistable")
	}
}

func TestLoadGraphForHook_SessionResetWithoutCrossFileState(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "session-A") // hook-built: no PackageIndex
	cg.AddNode(&FuncNode{ID: "f.go:F", FilePath: "f.go", Name: "F", Language: rules.LangGo})
	if err := SaveGraph(cg); err != nil {
		t.Fatal(err)
	}

	got, err := LoadGraphForHook(root, "session-B")
	if err != nil {
		t.Fatal(err)
	}
	// Original semantics: stale session graph is discarded.
	if got.SessionID != "session-B" {
		t.Errorf("SessionID = %q, want fresh session-B", got.SessionID)
	}
	if got.GetNode("f.go:F") != nil {
		t.Errorf("stale hook-session graph should not be adopted")
	}
}

func TestLoadGraphForHook_SameSessionLoadsNormally(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "session-A")
	cg.AddNode(&FuncNode{ID: "f.go:F", FilePath: "f.go", Name: "F", Language: rules.LangGo})
	if err := SaveGraph(cg); err != nil {
		t.Fatal(err)
	}
	got, err := LoadGraphForHook(root, "session-A")
	if err != nil {
		t.Fatal(err)
	}
	if got.GetNode("f.go:F") == nil {
		t.Errorf("same-session graph should load with its nodes")
	}
}

func TestLoadGraphForHook_MissingFileStartsFresh(t *testing.T) {
	root := t.TempDir()
	got, err := LoadGraphForHook(root, "s")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || len(got.Nodes) != 0 || got.SessionID != "s" {
		t.Errorf("missing graph file should yield a fresh graph; got %+v", got)
	}
	if got.SkipPersist {
		t.Errorf("fresh graph must be persistable")
	}
}

func TestLoadGraphForHook_OversizedGraphDeclinedWithSkipPersist(t *testing.T) {
	root := t.TempDir()
	cg := scanBuiltGraph(root, "")
	if err := SaveGraph(cg); err != nil {
		t.Fatal(err)
	}
	// Force the cap below the file's actual size via the env override.
	t.Setenv("BATOU_HOOK_CROSSFILE_MAX_MB", "1")
	info, err := os.Stat(GraphPath(root))
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > 1024*1024 {
		t.Fatalf("fixture graph unexpectedly larger than 1MB")
	}
	// 1MB cap > file size: adoption happens.
	got, err := LoadGraphForHook(root, "hook")
	if err != nil {
		t.Fatal(err)
	}
	if !got.HasCrossFileState() {
		t.Fatalf("graph under the cap should be adopted")
	}

	// Now shrink the cap to 0 — invalid, falls back to default. Use a
	// padded file instead: write junk to push the file over a 1MB cap.
	pad := make([]byte, 2*1024*1024)
	for i := range pad {
		pad[i] = ' '
	}
	f, err := os.OpenFile(GraphPath(root), os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(pad); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	got, err = LoadGraphForHook(root, "hook")
	if err != nil {
		t.Fatal(err)
	}
	if got.HasCrossFileState() {
		t.Fatalf("oversized graph should NOT be adopted")
	}
	if !got.SkipPersist {
		t.Errorf("declined-adoption graph must set SkipPersist so the hook save cannot clobber the scan-built file")
	}
}

func TestCallersOfFileFromOtherFiles(t *testing.T) {
	cg := NewCallGraph("/p", "")
	cg.AddNode(&FuncNode{ID: "b.go:Callee", FilePath: "b.go", Name: "Callee", Language: rules.LangGo})
	cg.AddNode(&FuncNode{ID: "a.go:Caller", FilePath: "a.go", Name: "Caller", Language: rules.LangGo})
	cg.AddNode(&FuncNode{ID: "b.go:Local", FilePath: "b.go", Name: "Local", Language: rules.LangGo})
	cg.AddEdge("a.go:Caller", "b.go:Callee")
	cg.AddEdge("b.go:Local", "b.go:Callee") // same-file: excluded

	got := CallersOfFileFromOtherFiles(cg, "b.go")
	if len(got) != 1 || got[0] != "a.go:Caller" {
		t.Errorf("CallersOfFileFromOtherFiles = %v, want [a.go:Caller]", got)
	}
	if got := CallersOfFileFromOtherFiles(cg, "zzz.go"); got != nil {
		t.Errorf("unknown file should yield nil, got %v", got)
	}
}

func TestCanonicalGraphPath_MapsAbsoluteToRelative(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "")
	cg.AddNode(&FuncNode{ID: "sub/x.go:F", FilePath: "sub/x.go", Name: "F", Language: rules.LangGo})

	abs := filepath.Join(root, "sub", "x.go")
	if got := CanonicalGraphPath(cg, abs); got != "sub/x.go" {
		t.Errorf("CanonicalGraphPath(%q) = %q, want sub/x.go", abs, got)
	}
	// Exact-match short-circuit.
	if got := CanonicalGraphPath(cg, "sub/x.go"); got != "sub/x.go" {
		t.Errorf("exact form should be returned as-is, got %q", got)
	}
	// Unknown file: identity.
	other := filepath.Join(root, "other.go")
	if got := CanonicalGraphPath(cg, other); got != other {
		t.Errorf("unknown file should be identity, got %q", got)
	}
	// Outside the project root: identity.
	if got := CanonicalGraphPath(cg, "/elsewhere/sub/x.go"); got != "/elsewhere/sub/x.go" {
		t.Errorf("out-of-root path should be identity, got %q", got)
	}
}

// TestResolveCrossFileEdgesForFile_RestoresBothDirections is the core
// incremental-resolve test: a two-file Go project whose cross-file edges
// were stripped (the way UpdateFileWithAST's RemoveFile does on a hook
// write) gets them back from a single-file resolve — outbound for the
// edited file, inbound via the alsoResolve caller list.
func TestResolveCrossFileEdgesForFile_RestoresBothDirections(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, map[string]string{
		"go.mod": "module example.com/app\n\ngo 1.21\n",
		"main.go": `package main

import (
	"net/http"

	"example.com/app/storage"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	storage.RunQuery(r.URL.Query().Get("q"))
}
`,
		"storage/db.go": `package storage

import "database/sql"

var db *sql.DB

func RunQuery(query string) {
	db.Exec(query)
}
`,
	})

	mainPath := filepath.Join(root, "main.go")
	dbPath := filepath.Join(root, "storage", "db.go")

	// Build the graph the way dirscan does: per-file extraction, then the
	// FULL cross-file pass (establishing PackageIndex / FileScopes /
	// FileModules — the persisted state the hook lane adopts).
	cg := NewCallGraph(root, "")
	mainSrc, _ := os.ReadFile(mainPath)
	dbSrc, _ := os.ReadFile(dbPath)
	UpdateFile(cg, mainPath, string(mainSrc), rules.LangGo)
	UpdateFile(cg, dbPath, string(dbSrc), rules.LangGo)
	full := ResolveCrossFileEdges(cg, root, nil)
	if full.CrossFileEdges == 0 {
		t.Fatalf("fixture broken: full pass resolved no cross-file edges (stats %+v)", full)
	}
	handlerID := mainPath + ":Handler"
	calleeID := dbPath + ":RunQuery"
	if !containsStr(cg.Nodes[handlerID].Calls, calleeID) {
		t.Fatalf("fixture broken: full pass did not produce %s -> %s", handlerID, calleeID)
	}

	// --- Outbound direction: hook write of main.go (the caller). ---
	// The edit changes Handler's BODY so the builder rebuilds the node
	// from scratch (no content-hash reuse) — the rebuilt node has only
	// same-file edges, the canonical post-write state.
	editedMain := []byte(strings.Replace(string(mainSrc), `Get("q")`, `Get("id")`, 1))
	inbound := CallersOfFileFromOtherFiles(cg, mainPath) // none expected
	UpdateFile(cg, mainPath, string(editedMain), rules.LangGo)
	if containsStr(cg.Nodes[handlerID].Calls, calleeID) {
		t.Fatalf("precondition: UpdateFile should have stripped the cross-file edge")
	}
	stats := ResolveCrossFileEdgesForFile(cg, root, mainPath, editedMain, inbound)
	if !containsStr(cg.Nodes[handlerID].Calls, calleeID) {
		t.Fatalf("outbound cross-file edge not restored (stats %+v)", stats)
	}
	if !containsStr(cg.Nodes[calleeID].CalledBy, handlerID) {
		t.Fatalf("callee back-edge not restored")
	}

	// --- Inbound direction: hook write of storage/db.go (the callee). ---
	// The body edit forces a fresh RunQuery node; RemoveFile strips the
	// caller's Calls edge into this file, which the alsoResolve list
	// must restore.
	editedDB := []byte(strings.Replace(string(dbSrc), "db.Exec(query)", "db.Exec(query) // edited", 1))
	inbound = CallersOfFileFromOtherFiles(cg, dbPath)
	if len(inbound) != 1 || inbound[0] != handlerID {
		t.Fatalf("inbound callers = %v, want [%s]", inbound, handlerID)
	}
	UpdateFile(cg, dbPath, string(editedDB), rules.LangGo)
	if containsStr(cg.Nodes[handlerID].Calls, calleeID) {
		t.Fatalf("precondition: callee rebuild should have stripped the caller's edge")
	}
	ResolveCrossFileEdgesForFile(cg, root, dbPath, editedDB, inbound)
	if !containsStr(cg.Nodes[handlerID].Calls, calleeID) {
		t.Fatalf("inbound cross-file edge not restored after callee edit")
	}
	if !containsStr(cg.Nodes[calleeID].CalledBy, handlerID) {
		t.Fatalf("callee back-edge not restored after callee edit")
	}

	// PackageIndex hygiene: rerunning the incremental pass must not
	// duplicate index entries.
	pkg := cg.PackageIndex.NodeToPackage[calleeID]
	before := len(cg.PackageIndex.PackageToNodes[pkg])
	ResolveCrossFileEdgesForFile(cg, root, dbPath, editedDB, inbound)
	after := len(cg.PackageIndex.PackageToNodes[pkg])
	if before != after {
		t.Errorf("PackageIndex entries grew on repeat resolve: %d -> %d", before, after)
	}
}

// TestResolveCrossFileEdgesForFile_NoOpWithoutCrossFileState pins the
// graceful-degradation contract: on a hook-only graph (no PackageIndex)
// the incremental pass must do nothing at all.
func TestResolveCrossFileEdgesForFile_NoOpWithoutCrossFileState(t *testing.T) {
	cg := NewCallGraph("/p", "s")
	cg.AddNode(&FuncNode{ID: "a.go:F", FilePath: "a.go", Name: "F", Language: rules.LangGo, RawCalls: []string{"pkg.G"}})
	stats := ResolveCrossFileEdgesForFile(cg, "/p", "a.go", []byte("package a"), nil)
	if stats != (ResolveStats{}) {
		t.Errorf("expected zero stats on graph without cross-file state, got %+v", stats)
	}
	if cg.PackageIndex != nil {
		t.Errorf("incremental pass must not fabricate cross-file state")
	}
}

// TestWalkCrossFileTaintFlowsForCaller_FindsCalleeSink mirrors the
// full-walk pair test but through the file-scoped entry point: the
// caller's file has an edge to a callee (different file) whose persisted
// signature carries a SQL sink fed by param 0.
func TestWalkCrossFileTaintFlowsForCaller_FindsCalleeSink(t *testing.T) {
	root := t.TempDir()
	aFile := filepath.Join(root, "a.go")
	bFile := filepath.Join(root, "b", "b.go")

	cg := NewCallGraph(root, "")
	cg.AddNode(&FuncNode{
		ID: aFile + ":Handler", FilePath: aFile, Name: "Handler",
		Language: rules.LangGo, StartLine: 3, EndLine: 5,
		TaintSig: TaintSignature{SourceParams: map[int]taint.SourceCategory{1: taint.SrcUserInput}},
	})
	cg.AddNode(&FuncNode{
		ID: bFile + ":RunQuery", FilePath: bFile, Name: "RunQuery",
		Language: rules.LangGo, StartLine: 5, EndLine: 8,
		TaintSig: TaintSignature{
			SinkCalls: []SinkRef{{SinkCategory: taint.SnkSQLQuery, MethodName: "db.Exec", Line: 6, ArgFromParam: 0}},
		},
	})
	cg.AddEdge(aFile+":Handler", bFile+":RunQuery")

	contents := map[string]string{
		aFile: "package a\nimport \"net/http\"\nfunc Handler(w http.ResponseWriter, r *http.Request) {\n\tRunQuery(r.URL.Query().Get(\"q\"))\n}\n",
	}
	findings := WalkCrossFileTaintFlowsForCaller(cg, aFile, contents)
	if len(findings) == 0 {
		t.Fatalf("expected a cross-file finding from the caller-scoped walk")
	}
	f := findings[0]
	if f.RuleID != "BATOU-INTERPROC-SQL_QUERY" {
		t.Errorf("RuleID = %q, want BATOU-INTERPROC-SQL_QUERY", f.RuleID)
	}
	sawCalleeFile := false
	for _, st := range f.TaintPath {
		if st.File == bFile && st.Kind == rules.TaintStepSink {
			sawCalleeFile = true
		}
	}
	if !sawCalleeFile {
		t.Errorf("taint path should reach the callee file's sink; got %+v", f.TaintPath)
	}

	// Scoping: walking a DIFFERENT file produces nothing.
	if got := WalkCrossFileTaintFlowsForCaller(cg, bFile, contents); len(got) != 0 {
		t.Errorf("callee-file walk should be empty (no outbound edges), got %d findings", len(got))
	}
	// Determinism: same inputs, same findings.
	again := WalkCrossFileTaintFlowsForCaller(cg, aFile, contents)
	if len(again) != len(findings) {
		t.Errorf("walk not deterministic: %d vs %d findings", len(findings), len(again))
	}
}

func writeFixture(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
