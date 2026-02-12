package graph_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/turen/gtss/internal/graph"
	"github.com/turen/gtss/internal/rules"
	"github.com/turen/gtss/internal/taint"
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
	want := "/project/.gtss/callgraph.json"
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
	gtssDir := filepath.Clean(filepath.Join(tmpDir, ".gtss"))
	if !strings.HasPrefix(gtssDir, filepath.Clean(tmpDir)) {
		t.Fatal("unexpected path traversal")
	}
	if err := guardedMkdirAll(tmpDir, gtssDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	corruptFile := filepath.Clean(filepath.Join(gtssDir, "callgraph.json"))
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

// ---------------------------------------------------------------------------
// SaveGraph creates .gtss directory
// ---------------------------------------------------------------------------

func TestSaveGraphCreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	cg := graph.NewCallGraph(tmpDir, "session-1")
	if err := graph.SaveGraph(cg); err != nil {
		t.Fatalf("SaveGraph: %v", err)
	}

	expectedDir := filepath.Clean(filepath.Join(tmpDir, ".gtss"))
	if !strings.HasPrefix(expectedDir, filepath.Clean(tmpDir)) {
		t.Fatal("unexpected path traversal")
	}
	info, err := guardedStat(tmpDir, expectedDir)
	if err != nil {
		t.Fatalf(".gtss directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Error(".gtss should be a directory")
	}
}
