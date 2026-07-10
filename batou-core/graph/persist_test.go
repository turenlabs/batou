package graph_test

import (
	"bytes"
	"github.com/turenlabs/batou-core/graph"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// guardedStat wraps os.Stat with filepath.Clean + strings.HasPrefix validation.
func guardedStat(base, target string) (os.FileInfo, error) {
	cleaned := filepath.Clean(target)
	if !strings.HasPrefix(cleaned, filepath.Clean(base)) {
		return nil, os.ErrPermission
	}
	return os.Stat(cleaned)
}

// guardedMkdirAll wraps os.MkdirAll with filepath.Clean + strings.HasPrefix validation.
func guardedMkdirAll(base, target string, perm os.FileMode) error {
	cleaned := filepath.Clean(target)
	if !strings.HasPrefix(cleaned, filepath.Clean(base)) {
		return os.ErrPermission
	}
	return os.MkdirAll(cleaned, perm)
}

// guardedWriteFile wraps os.WriteFile with filepath.Clean + strings.HasPrefix validation.
func guardedWriteFile(base, target string, data []byte, perm os.FileMode) error {
	cleaned := filepath.Clean(target)
	if !strings.HasPrefix(cleaned, filepath.Clean(base)) {
		return os.ErrPermission
	}
	return os.WriteFile(cleaned, data, perm)
}

// ---------------------------------------------------------------------------
// GraphPath
// ---------------------------------------------------------------------------

func TestGraphPath(t *testing.T) {
	got := graph.GraphPath("/project")
	want := "/project/.batou/callgraph.json"
	if got != want {
		t.Errorf("GraphPath = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// SaveGraph / LoadGraph round-trip
// ---------------------------------------------------------------------------

func TestSaveAndLoadRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()

	cg := graph.NewCallGraph(tmpDir, "session-42")
	node := &graph.FuncNode{
		ID:          "handler.go:Handler",
		FilePath:    "handler.go",
		Name:        "Handler",
		Package:     "main",
		StartLine:   1,
		EndLine:     10,
		ContentHash: "abc123",
		Language:    rules.LangGo,
		TaintSig: graph.TaintSignature{
			TaintedParams: map[int][]taint.SourceCategory{
				0: {taint.SrcUserInput},
			},
			SinkCalls: []graph.SinkRef{
				{SinkCategory: taint.SnkSQLQuery, MethodName: "Query", Line: 5},
			},
		},
	}
	cg.AddNode(node)

	if err := graph.SaveGraph(cg); err != nil {
		t.Fatalf("SaveGraph failed: %v", err)
	}

	// Verify the file was created via guarded stat.
	graphFile := graph.GraphPath(tmpDir)
	if _, err := guardedStat(tmpDir, graphFile); err != nil {
		t.Fatalf("graph file not created: %v", err)
	}

	// Load it back.
	loaded, err := graph.LoadGraph(tmpDir, "session-42")
	if err != nil {
		t.Fatalf("LoadGraph failed: %v", err)
	}

	if loaded.SessionID != "session-42" {
		t.Errorf("loaded SessionID = %q, want %q", loaded.SessionID, "session-42")
	}
	if loaded.ProjectRoot != tmpDir {
		t.Errorf("loaded ProjectRoot = %q, want %q", loaded.ProjectRoot, tmpDir)
	}

	loadedNode := loaded.GetNode("handler.go:Handler")
	if loadedNode == nil {
		t.Fatal("expected node handler.go:Handler in loaded graph")
	}
	if loadedNode.Name != "Handler" {
		t.Errorf("loaded node Name = %q, want %q", loadedNode.Name, "Handler")
	}
	if loadedNode.ContentHash != "abc123" {
		t.Errorf("loaded node ContentHash = %q, want %q", loadedNode.ContentHash, "abc123")
	}
	if len(loadedNode.TaintSig.TaintedParams) != 1 {
		t.Errorf("loaded TaintedParams length = %d, want 1", len(loadedNode.TaintSig.TaintedParams))
	}
	if len(loadedNode.TaintSig.SinkCalls) != 1 {
		t.Errorf("loaded SinkCalls length = %d, want 1", len(loadedNode.TaintSig.SinkCalls))
	}
}

// TestSaveAndLoadRoundTrip_FieldSensitiveSchema exercises the three
// additive PR3 fields (SinkRef.ArgFieldPath, TaintSignature.Tainted-
// ReturnPaths, ParamTaint.FieldName — including MULTIPLE ParamTaint rows
// sharing one Index for a destructured binding) through a full
// Save/Load JSON round-trip, proving they persist and reload intact.
func TestSaveAndLoadRoundTrip_FieldSensitiveSchema(t *testing.T) {
	tmpDir := t.TempDir()

	cg := graph.NewCallGraph(tmpDir, "session-fs")
	node := &graph.FuncNode{
		ID:        "run.js:run",
		FilePath:  "run.js",
		Name:      "run",
		StartLine: 1,
		EndLine:   3,
		Language:  rules.LangJavaScript,
		TaintSig: graph.TaintSignature{
			// Field-sensitive sink: reads opts.cmd off param 0.
			SinkCalls: []graph.SinkRef{
				{
					SinkCategory: taint.SnkCommand,
					MethodName:   "exec",
					Line:         2,
					ArgFromParam: 0,
					ArgFieldPath: "cmd",
				},
			},
			// Field-sensitive return: 0.user.id is tainted; name is not.
			TaintedReturnPaths: map[string][]taint.SourceCategory{
				"0.user.id": {taint.SrcUserInput},
			},
			// Destructured binding: two ParamTaint rows share Index 0.
			Params: []graph.ParamTaint{
				{Index: 0, Name: "cmd", FieldName: "cmd"},
				{Index: 0, Name: "safe", FieldName: "safe"},
			},
		},
	}
	cg.AddNode(node)

	if err := graph.SaveGraph(cg); err != nil {
		t.Fatalf("SaveGraph failed: %v", err)
	}
	loaded, err := graph.LoadGraph(tmpDir, "session-fs")
	if err != nil {
		t.Fatalf("LoadGraph failed: %v", err)
	}

	ln := loaded.GetNode("run.js:run")
	if ln == nil {
		t.Fatal("expected node run.js:run in loaded graph")
	}

	// 1. SinkRef.ArgFieldPath survives.
	if len(ln.TaintSig.SinkCalls) != 1 {
		t.Fatalf("loaded SinkCalls length = %d, want 1", len(ln.TaintSig.SinkCalls))
	}
	if got := ln.TaintSig.SinkCalls[0].ArgFieldPath; got != "cmd" {
		t.Errorf("loaded SinkRef.ArgFieldPath = %q, want %q", got, "cmd")
	}
	if got := ln.TaintSig.SinkCalls[0].ArgFromParam; got != 0 {
		t.Errorf("loaded SinkRef.ArgFromParam = %d, want 0", got)
	}

	// 2. TaintedReturnPaths survives with the exact path key + category.
	cats, ok := ln.TaintSig.TaintedReturnPaths["0.user.id"]
	if !ok {
		t.Fatalf("loaded TaintedReturnPaths missing key %q; got %v", "0.user.id", ln.TaintSig.TaintedReturnPaths)
	}
	if len(cats) != 1 || cats[0] != taint.SrcUserInput {
		t.Errorf("loaded TaintedReturnPaths[0.user.id] = %v, want [%s]", cats, taint.SrcUserInput)
	}

	// 3. Multiple ParamTaint rows sharing Index 0 + FieldName survive.
	if len(ln.TaintSig.Params) != 2 {
		t.Fatalf("loaded Params length = %d, want 2 (destructured)", len(ln.TaintSig.Params))
	}
	byField := map[string]graph.ParamTaint{}
	for _, p := range ln.TaintSig.Params {
		if p.Index != 0 {
			t.Errorf("loaded Param %q has Index %d, want 0 (shared)", p.Name, p.Index)
		}
		byField[p.FieldName] = p
	}
	if _, ok := byField["cmd"]; !ok {
		t.Errorf("loaded Params missing FieldName %q", "cmd")
	}
	if _, ok := byField["safe"]; !ok {
		t.Errorf("loaded Params missing FieldName %q", "safe")
	}
}

// TestSaveAndLoadRoundTrip_LegacyFieldsZero proves backward-compat: a node
// persisted WITHOUT the PR3 fields reloads with them at their zero values
// (empty string / nil), so a legacy on-disk graph falls through to the
// whole-param / whole-return logic with no behaviour change.
func TestSaveAndLoadRoundTrip_LegacyFieldsZero(t *testing.T) {
	tmpDir := t.TempDir()
	cg := graph.NewCallGraph(tmpDir, "session-legacy")
	cg.AddNode(&graph.FuncNode{
		ID:       "legacy.js:run",
		FilePath: "legacy.js",
		Name:     "run",
		Language: rules.LangJavaScript,
		TaintSig: graph.TaintSignature{
			SinkCalls: []graph.SinkRef{
				{SinkCategory: taint.SnkCommand, MethodName: "exec", Line: 2, ArgFromParam: 0},
			},
			TaintedReturns: map[int][]taint.SourceCategory{0: {taint.SrcUserInput}},
		},
	})
	if err := graph.SaveGraph(cg); err != nil {
		t.Fatalf("SaveGraph: %v", err)
	}
	loaded, err := graph.LoadGraph(tmpDir, "session-legacy")
	if err != nil {
		t.Fatalf("LoadGraph: %v", err)
	}
	ln := loaded.GetNode("legacy.js:run")
	if ln == nil {
		t.Fatal("expected legacy node")
	}
	if ln.TaintSig.SinkCalls[0].ArgFieldPath != "" {
		t.Errorf("legacy SinkRef.ArgFieldPath = %q, want empty (whole-param)", ln.TaintSig.SinkCalls[0].ArgFieldPath)
	}
	if ln.TaintSig.TaintedReturnPaths != nil {
		t.Errorf("legacy TaintedReturnPaths = %v, want nil (whole-return)", ln.TaintSig.TaintedReturnPaths)
	}
	// Whole-return still present and intact.
	if len(ln.TaintSig.TaintedReturns) != 1 {
		t.Errorf("legacy TaintedReturns length = %d, want 1", len(ln.TaintSig.TaintedReturns))
	}
}

func TestSaveAndLoadRoundTrip_FileTaintCache(t *testing.T) {
	tmpDir := t.TempDir()

	cg := graph.NewCallGraph(tmpDir, "session-tc")
	hash := graph.FileContentHash("package main\nfunc handler() {}")
	cg.SetFileTaintCache("/app/handler.go", hash, 0)
	cg.SetFileTaintCache("/app/service.go", graph.FileContentHash("package main"), 5)

	if err := graph.SaveGraph(cg); err != nil {
		t.Fatalf("SaveGraph failed: %v", err)
	}

	loaded, err := graph.LoadGraph(tmpDir, "session-tc")
	if err != nil {
		t.Fatalf("LoadGraph failed: %v", err)
	}

	// Check the clean file cache entry.
	entry := loaded.GetFileTaintCache("/app/handler.go")
	if entry == nil {
		t.Fatal("expected cache entry for /app/handler.go after round-trip")
	}
	if entry.ContentHash != hash {
		t.Errorf("ContentHash = %d, want %d", entry.ContentHash, hash)
	}
	if entry.FlowCount != 0 {
		t.Errorf("FlowCount = %d, want 0", entry.FlowCount)
	}

	// Check the file with flows.
	entry2 := loaded.GetFileTaintCache("/app/service.go")
	if entry2 == nil {
		t.Fatal("expected cache entry for /app/service.go after round-trip")
	}
	if entry2.FlowCount != 5 {
		t.Errorf("FlowCount = %d, want 5", entry2.FlowCount)
	}

	// Non-existent file should still return nil.
	if loaded.GetFileTaintCache("/app/nonexistent.go") != nil {
		t.Error("expected nil for non-existent file path in loaded cache")
	}
}

// ---------------------------------------------------------------------------
// LoadGraph with non-existent file
// ---------------------------------------------------------------------------

func TestLoadGraphNoFile(t *testing.T) {
	tmpDir := t.TempDir()

	cg, err := graph.LoadGraph(tmpDir, "session-1")
	if err != nil {
		t.Fatalf("LoadGraph should not error for missing file: %v", err)
	}
	if len(cg.Nodes) != 0 {
		t.Errorf("expected empty graph, got %d nodes", len(cg.Nodes))
	}
	if cg.SessionID != "session-1" {
		t.Errorf("new graph SessionID = %q, want %q", cg.SessionID, "session-1")
	}
}

// ---------------------------------------------------------------------------
// LoadGraph with different session ID (stale graph)
// ---------------------------------------------------------------------------

func TestLoadGraphStaleSession(t *testing.T) {
	tmpDir := t.TempDir()

	// Save with session-1.
	cg := graph.NewCallGraph(tmpDir, "session-1")
	cg.AddNode(&graph.FuncNode{ID: "f:A", FilePath: "f", Name: "A"})
	if err := graph.SaveGraph(cg); err != nil {
		t.Fatalf("SaveGraph: %v", err)
	}

	// Load with session-2 — should get fresh graph.
	loaded, err := graph.LoadGraph(tmpDir, "session-2")
	if err != nil {
		t.Fatalf("LoadGraph: %v", err)
	}
	if loaded.SessionID != "session-2" {
		t.Errorf("SessionID = %q, want %q", loaded.SessionID, "session-2")
	}
	if len(loaded.Nodes) != 0 {
		t.Error("expected fresh graph (no nodes) for different session ID")
	}
}

// ---------------------------------------------------------------------------
// LoadGraph with corrupted file
// ---------------------------------------------------------------------------

func TestLoadGraphCorruptedFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Write corrupt data to the graph location using guarded helpers.
	batouDir := filepath.Clean(filepath.Join(tmpDir, ".batou"))
	if !strings.HasPrefix(batouDir, filepath.Clean(tmpDir)) {
		t.Fatal("unexpected path traversal")
	}
	if err := guardedMkdirAll(tmpDir, batouDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	corruptFile := filepath.Clean(filepath.Join(batouDir, "callgraph.json"))
	if !strings.HasPrefix(corruptFile, filepath.Clean(tmpDir)) {
		t.Fatal("unexpected path traversal")
	}
	if err := guardedWriteFile(tmpDir, corruptFile, []byte("not valid json{{{"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Should return a fresh graph, not an error.
	cg, err := graph.LoadGraph(tmpDir, "session-1")
	if err != nil {
		t.Fatalf("LoadGraph with corrupt file should not error: %v", err)
	}
	if len(cg.Nodes) != 0 {
		t.Error("expected fresh graph for corrupted file")
	}
}

// TestLoadGraphOversizeFile verifies the DoS ceiling: a graph file larger
// than the (env-overridable) cap is treated as absent — the scan rebuilds
// from scratch instead of reading an attacker-supplied multi-GB file into
// memory. The persisted bytes are valid JSON so this exercises the
// size-gate, not the corrupt-file path.
func TestLoadGraphOversizeFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Build a real, loadable graph so the file is valid JSON with a node.
	cg := graph.NewCallGraph(tmpDir, "session-big")
	cg.AddNode(&graph.FuncNode{ID: "g:Big", Name: "Big", FilePath: "big.go", Language: rules.LangGo})
	if err := graph.SaveGraph(cg); err != nil {
		t.Fatalf("SaveGraph: %v", err)
	}

	graphFile := filepath.Clean(filepath.Join(tmpDir, ".batou", "callgraph.json"))
	if !strings.HasPrefix(graphFile, filepath.Clean(tmpDir)) {
		t.Fatal("unexpected path traversal")
	}
	info, err := guardedStat(tmpDir, graphFile)
	if err != nil {
		t.Fatalf("stat graph: %v", err)
	}

	// Cap at 1MB (the minimum whole-megabyte override). The written graph is
	// tiny, so pad the file past 1MB with a trailing JSON-comment-free filler
	// that keeps json.Unmarshal happy is unnecessary — the size-gate runs
	// BEFORE any parse, so we just need the byte length over the cap.
	if info.Size() >= 1024*1024 {
		t.Fatalf("baseline graph unexpectedly large (%d bytes); test assumes < 1MB", info.Size())
	}
	pad := make([]byte, 1024*1024)                                   // 1 MiB of NUL — pushes total over the 1MB cap
	f, err := os.OpenFile(graphFile, os.O_APPEND|os.O_WRONLY, 0o644) // #nosec G304 -- test-controlled temp path
	if err != nil {
		t.Fatalf("open for append: %v", err)
	}
	if _, err := f.Write(pad); err != nil {
		_ = f.Close()
		t.Fatalf("pad write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	t.Setenv("BATOU_MAX_GRAPH_MB", "1")

	loaded, err := graph.LoadGraph(tmpDir, "session-big")
	if err != nil {
		t.Fatalf("LoadGraph over cap should not error: %v", err)
	}
	if len(loaded.Nodes) != 0 {
		t.Errorf("expected fresh (empty) graph for oversize file, got %d nodes", len(loaded.Nodes))
	}
}

// ---------------------------------------------------------------------------
// SaveGraph creates .batou directory
// ---------------------------------------------------------------------------

func TestSaveGraphCreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	cg := graph.NewCallGraph(tmpDir, "session-1")
	if err := graph.SaveGraph(cg); err != nil {
		t.Fatalf("SaveGraph: %v", err)
	}

	expectedDir := filepath.Clean(filepath.Join(tmpDir, ".batou"))
	if !strings.HasPrefix(expectedDir, filepath.Clean(tmpDir)) {
		t.Fatal("unexpected path traversal")
	}
	info, err := guardedStat(tmpDir, expectedDir)
	if err != nil {
		t.Fatalf(".batou directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Error(".batou should be a directory")
	}
}

// ---------------------------------------------------------------------------
// SaveGraph: creates .batou even when its parent is several dirs deep, and
// stays stderr-clean on success.
// ---------------------------------------------------------------------------

// captureStderr redirects os.Stderr to a pipe, runs fn, restores stderr, and
// returns whatever fn wrote. Used by tests that need to verify SaveGraph
// stays quiet on the happy path (the pre-fix code emitted "graph temp
// cleanup: …" and "renaming temp graph file: …" lines under concurrency).
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stderr
	os.Stderr = w
	done := make(chan struct{})
	var buf bytes.Buffer
	go func() {
		_, _ = io.Copy(&buf, r)
		close(done)
	}()
	fn()
	_ = w.Close()
	<-done
	os.Stderr = orig
	_ = r.Close()
	return buf.String()
}

func TestSaveGraphCreatesNestedDirectory(t *testing.T) {
	// projectRoot points at a not-yet-existent grandchild directory. SaveGraph
	// must MkdirAll the full chain — the bug we're fixing here surfaced
	// because callers assumed the parent existed and only the final .batou
	// component was missing.
	tmpDir := t.TempDir()
	deep := filepath.Join(tmpDir, "a", "b", "c", "project")

	cg := graph.NewCallGraph(deep, "session-deep")
	stderrOut := captureStderr(t, func() {
		if err := graph.SaveGraph(cg); err != nil {
			t.Fatalf("SaveGraph: %v", err)
		}
	})
	if stderrOut != "" {
		t.Errorf("expected clean stderr on success, got:\n%s", stderrOut)
	}
	wantFile := filepath.Join(deep, ".batou", "callgraph.json")
	if _, err := os.Stat(wantFile); err != nil {
		t.Fatalf("graph file not created at %s: %v", wantFile, err)
	}
}

// TestSaveGraphConcurrentRace exercises the regression that previously emitted
// "graph temp cleanup: ... no such file or directory" and "renaming temp graph
// file: ... no such file or directory" on every `batou scan` of a real-world
// codebase. The old SaveGraph wrote to a shared "<graphFile>.tmp" path, and
// concurrent SaveGraph calls in the same process raced on it: goroutine A's
// rename would consume the shared tmp before goroutine B reached its rename.
//
// The fix is per-call os.CreateTemp tmp names plus a fs.ErrNotExist-aware
// cleanup. This test runs many concurrent SaveGraph calls and asserts that:
//
//  1. None of them return errors.
//  2. Nothing is written to stderr (the old code printed two lines per race).
//  3. The final graph file exists and is valid JSON-shaped.
func TestSaveGraphConcurrentRace(t *testing.T) {
	tmpDir := t.TempDir()

	const goroutines = 32
	cgs := make([]*graph.CallGraph, goroutines)
	for i := range cgs {
		cgs[i] = graph.NewCallGraph(tmpDir, "session-race")
		// Distinct node per goroutine so each Save serializes different
		// content; concurrent identical-content writes wouldn't exercise
		// the tmp-name race the same way.
		cgs[i].AddNode(&graph.FuncNode{ID: "f:" + filepath.Base(tmpDir), Name: "F", FilePath: "f"})
	}

	stderrOut := captureStderr(t, func() {
		var wg sync.WaitGroup
		errs := make(chan error, goroutines)
		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				if err := graph.SaveGraph(cgs[idx]); err != nil {
					errs <- err
				}
			}(i)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Errorf("concurrent SaveGraph failed: %v", err)
		}
	})
	if stderrOut != "" {
		t.Errorf("expected clean stderr under concurrency, got:\n%s", stderrOut)
	}

	// The final on-disk file should be a complete graph (parsable, with the
	// one node we inserted).
	loaded, err := graph.LoadGraph(tmpDir, "session-race")
	if err != nil {
		t.Fatalf("LoadGraph after concurrent saves: %v", err)
	}
	if len(loaded.Nodes) == 0 {
		t.Error("expected at least one node in graph after concurrent saves")
	}

	// Also: no stray tmp files should remain alongside the graph. The
	// per-call os.CreateTemp names use the pattern "callgraph.*.json.tmp".
	entries, err := os.ReadDir(filepath.Join(tmpDir, ".batou"))
	if err != nil {
		t.Fatalf("reading .batou dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("leftover tmp file in .batou/: %s", e.Name())
		}
	}
}

// ---------------------------------------------------------------------------
// SaveGraphAt / LoadGraphAt round-trip with an explicit (non-default) path.
// ---------------------------------------------------------------------------

func TestSaveGraphAtExplicitPath(t *testing.T) {
	tmpDir := t.TempDir()
	altPath := filepath.Join(tmpDir, "subdir", "callgraph.json")

	cg := graph.NewCallGraph(tmpDir, "session-at")
	cg.AddNode(&graph.FuncNode{ID: "g:Foo", Name: "Foo", FilePath: "g"})

	if err := graph.SaveGraphAt(cg, altPath); err != nil {
		t.Fatalf("SaveGraphAt: %v", err)
	}

	if _, err := os.Stat(altPath); err != nil {
		t.Fatalf("expected graph at explicit path %s: %v", altPath, err)
	}
	// Default .batou path should NOT have been created.
	if _, err := os.Stat(filepath.Join(tmpDir, ".batou", "callgraph.json")); !os.IsNotExist(err) {
		t.Errorf("default .batou path should not exist when using SaveGraphAt; stat err = %v", err)
	}

	loaded, err := graph.LoadGraphAt(altPath, tmpDir, "session-at")
	if err != nil {
		t.Fatalf("LoadGraphAt: %v", err)
	}
	if loaded.GetNode("g:Foo") == nil {
		t.Error("expected node g:Foo after LoadGraphAt round-trip")
	}
}
