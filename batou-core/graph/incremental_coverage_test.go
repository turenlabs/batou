package graph

// Internal-package coverage tests for the under-exercised incremental
// (hook-lane) cross-file plumbing in incremental.go:
//
//   - ensureFileScopeFromDisk: every guarded early-return plus the
//     disk-read-and-cache success path (was 11.1%).
//   - reindexFileNodes: the stale-ID sweep and the package-remap branch
//     (was 55.2%).
//   - CallersOfFileFromOtherFiles: the > maxIncrementalCallers cap.
//
// These call unexported helpers and inspect PackageIndex internals, so they
// live in package `graph` (white-box) rather than `graph_test`.

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// ---------------------------------------------------------------------------
// ensureFileScopeFromDisk: guarded early-returns + the disk-read success path.
// ---------------------------------------------------------------------------

func TestEnsureFileScopeFromDisk_AlreadyPresent(t *testing.T) {
	cg := NewCallGraph("/p", "")
	cg.FileScopes = map[string]FileScope{
		"/p/a.go": {Package: "preexisting"},
	}
	// Even with no nodes/resolver/file on disk, an existing scope short-
	// circuits before any of that is consulted and is left untouched.
	ensureFileScopeFromDisk(cg, "/p/a.go", "/p")
	if got := cg.FileScopes["/p/a.go"].Package; got != "preexisting" {
		t.Errorf("existing scope must not be overwritten, got Package=%q", got)
	}
}

func TestEnsureFileScopeFromDisk_NoNodesForFile(t *testing.T) {
	cg := NewCallGraph("/p", "")
	cg.FileScopes = map[string]FileScope{}
	// No node has FilePath "/p/ghost.go" => NodesInFile is empty => return
	// before touching the filesystem; no scope recorded.
	ensureFileScopeFromDisk(cg, "/p/ghost.go", "/p")
	if _, ok := cg.FileScopes["/p/ghost.go"]; ok {
		t.Error("a file with no nodes must not get a scope")
	}
}

func TestEnsureFileScopeFromDisk_UnknownLanguageNoResolver(t *testing.T) {
	cg := NewCallGraph("/p", "")
	cg.FileScopes = map[string]FileScope{}
	// LangSQL has no registered resolver in the graph package =>
	// GetResolver returns nil => early return.
	cg.AddNode(&FuncNode{ID: "/p/x.sql:F", FilePath: "/p/x.sql", Name: "F", Language: rules.LangSQL})
	ensureFileScopeFromDisk(cg, "/p/x.sql", "/p")
	if _, ok := cg.FileScopes["/p/x.sql"]; ok {
		t.Error("a file whose language has no resolver must not get a scope")
	}
}

func TestEnsureFileScopeFromDisk_FileMissingOnDisk(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "")
	cg.FileScopes = map[string]FileScope{}
	missing := filepath.Join(root, "nope.go")
	cg.AddNode(&FuncNode{ID: missing + ":F", FilePath: missing, Name: "F", Language: rules.LangGo})
	// os.Stat fails (file absent) => return without recording a scope.
	ensureFileScopeFromDisk(cg, missing, root)
	if _, ok := cg.FileScopes[missing]; ok {
		t.Error("a file absent from disk must not get a scope")
	}
}

func TestEnsureFileScopeFromDisk_DirectoryPath(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "")
	cg.FileScopes = map[string]FileScope{}
	dir := filepath.Join(root, "subdir")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	cg.AddNode(&FuncNode{ID: dir + ":F", FilePath: dir, Name: "F", Language: rules.LangGo})
	// info.IsDir() => skip.
	ensureFileScopeFromDisk(cg, dir, root)
	if _, ok := cg.FileScopes[dir]; ok {
		t.Error("a directory path must not get a scope")
	}
}

func TestEnsureFileScopeFromDisk_ReadsAndCachesFromDisk(t *testing.T) {
	root := t.TempDir()
	src := `package widgets

import "database/sql"

var db *sql.DB

func Run(q string) { db.Exec(q) }
`
	path := filepath.Join(root, "widgets.go")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	cg := NewCallGraph(root, "")
	cg.FileScopes = map[string]FileScope{} // scope ABSENT — forces the disk read
	cg.AddNode(&FuncNode{ID: path + ":Run", FilePath: path, Name: "Run", Language: rules.LangGo})

	ensureFileScopeFromDisk(cg, path, root)

	scope, ok := cg.FileScopes[path]
	if !ok {
		t.Fatal("scope should have been extracted from disk and cached")
	}
	if scope.Package != "widgets" {
		t.Errorf("extracted scope Package = %q, want widgets", scope.Package)
	}
}

// ---------------------------------------------------------------------------
// reindexFileNodes: the stale-ID sweep and the package-remap branch.
// ---------------------------------------------------------------------------

// A NodeToPackage entry keyed under this file whose node no longer exists
// must be dropped from BOTH maps, and the now-empty package bucket removed.
func TestReindexFileNodes_DropsStaleEntries(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"),
		[]byte("module example.com/app\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "svc.go")

	cg := NewCallGraph(root, "")
	cg.ModulePaths = map[rules.Language]string{rules.LangGo: "example.com/app"}
	cg.ModuleRoots = map[rules.Language]string{rules.LangGo: root}
	cg.PackageIndex = NewPackageIndex()

	staleID := path + ":Removed"
	livePkg := "example.com/app"
	// Pre-seed a stale index entry (its node is NOT in cg.Nodes).
	cg.PackageIndex.Add(livePkg, staleID)

	// A live node currently in the file.
	live := &FuncNode{ID: path + ":Live", FilePath: path, Name: "Live", Language: rules.LangGo}
	cg.AddNode(live)

	reindexFileNodes(cg, path, root, []*FuncNode{live})

	if _, ok := cg.PackageIndex.NodeToPackage[staleID]; ok {
		t.Errorf("stale node %q should have been removed from NodeToPackage", staleID)
	}
	if containsStr(cg.PackageIndex.PackageToNodes[livePkg], staleID) {
		t.Errorf("stale node %q should have been removed from PackageToNodes", staleID)
	}
	// The live node should now be indexed under the module package.
	if cg.PackageIndex.NodeToPackage[live.ID] != livePkg {
		t.Errorf("live node package = %q, want %q", cg.PackageIndex.NodeToPackage[live.ID], livePkg)
	}
}

// A node already indexed under a DIFFERENT package must be re-keyed: dropped
// from the old bucket (emptied bucket deleted) and added to the new one.
func TestReindexFileNodes_RemapsChangedPackage(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"),
		[]byte("module example.com/app\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "svc.go")

	cg := NewCallGraph(root, "")
	cg.ModulePaths = map[rules.Language]string{rules.LangGo: "example.com/app"}
	cg.ModuleRoots = map[rules.Language]string{rules.LangGo: root}
	cg.PackageIndex = NewPackageIndex()

	node := &FuncNode{ID: path + ":F", FilePath: path, Name: "F", Language: rules.LangGo}
	cg.AddNode(node)

	// Pre-index the node under a WRONG/old package so the remap branch fires.
	oldPkg := "example.com/app/old"
	cg.PackageIndex.Add(oldPkg, node.ID)

	reindexFileNodes(cg, path, root, []*FuncNode{node})

	newPkg := importPathForNode(cg, node, root)
	if newPkg == oldPkg {
		t.Fatalf("test precondition broken: import path %q unexpectedly equals oldPkg", newPkg)
	}
	if cg.PackageIndex.NodeToPackage[node.ID] != newPkg {
		t.Errorf("node re-keyed to %q, want %q", cg.PackageIndex.NodeToPackage[node.ID], newPkg)
	}
	if _, ok := cg.PackageIndex.PackageToNodes[oldPkg]; ok {
		t.Errorf("emptied old package bucket %q should have been deleted", oldPkg)
	}
	if !containsStr(cg.PackageIndex.PackageToNodes[newPkg], node.ID) {
		t.Errorf("node not present in new package bucket %q", newPkg)
	}
}

// A node already indexed under the CORRECT package is left untouched (the
// `old == pkg { continue }` short-circuit) — repeated calls don't duplicate.
func TestReindexFileNodes_IdempotentForUnchangedPackage(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"),
		[]byte("module example.com/app\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "svc.go")

	cg := NewCallGraph(root, "")
	cg.ModulePaths = map[rules.Language]string{rules.LangGo: "example.com/app"}
	cg.ModuleRoots = map[rules.Language]string{rules.LangGo: root}
	cg.PackageIndex = NewPackageIndex()

	node := &FuncNode{ID: path + ":F", FilePath: path, Name: "F", Language: rules.LangGo}
	cg.AddNode(node)

	reindexFileNodes(cg, path, root, []*FuncNode{node})
	pkg := cg.PackageIndex.NodeToPackage[node.ID]
	if pkg == "" {
		t.Fatal("node was not indexed on first pass")
	}
	before := len(cg.PackageIndex.PackageToNodes[pkg])

	reindexFileNodes(cg, path, root, []*FuncNode{node})
	after := len(cg.PackageIndex.PackageToNodes[pkg])
	if before != after {
		t.Errorf("repeat reindex duplicated bucket entries: %d -> %d", before, after)
	}
}

// reindexFileNodes is a no-op (and never panics) when the graph has no
// PackageIndex at all.
func TestReindexFileNodes_NilPackageIndex(t *testing.T) {
	cg := NewCallGraph("/p", "")
	node := &FuncNode{ID: "/p/a.go:F", FilePath: "/p/a.go", Name: "F", Language: rules.LangGo}
	cg.AddNode(node)
	reindexFileNodes(cg, "/p/a.go", "/p", []*FuncNode{node}) // pi == nil branch
	if cg.PackageIndex != nil {
		t.Error("reindex must not fabricate a PackageIndex")
	}
}

// A node whose importPathForNode returns "" (outside any known module) is
// skipped entirely — no index entry is created.
func TestReindexFileNodes_SkipsNodeWithNoImportPath(t *testing.T) {
	cg := NewCallGraph("/p", "")
	cg.PackageIndex = NewPackageIndex()
	// No ModulePaths => importPathForNode returns "" for a Go node.
	node := &FuncNode{ID: "/p/a.go:F", FilePath: "/p/a.go", Name: "F", Language: rules.LangGo}
	cg.AddNode(node)
	reindexFileNodes(cg, "/p/a.go", "/p", []*FuncNode{node})
	if _, ok := cg.PackageIndex.NodeToPackage[node.ID]; ok {
		t.Error("node outside any module must not be indexed")
	}
}

// ---------------------------------------------------------------------------
// CallersOfFileFromOtherFiles: the > maxIncrementalCallers cap.
// ---------------------------------------------------------------------------

func TestCallersOfFileFromOtherFiles_CapsAtMax(t *testing.T) {
	cg := NewCallGraph("/p", "")
	calleeFile := "callee.go"
	cg.AddNode(&FuncNode{ID: calleeFile + ":Target", FilePath: calleeFile, Name: "Target", Language: rules.LangGo})

	// Create more cross-file callers than the cap.
	total := maxIncrementalCallers + 25
	for i := 0; i < total; i++ {
		caller := "caller" + strconv.Itoa(i) + ".go"
		id := caller + ":C"
		cg.AddNode(&FuncNode{ID: id, FilePath: caller, Name: "C", Language: rules.LangGo})
		cg.AddEdge(id, calleeFile+":Target")
	}

	got := CallersOfFileFromOtherFiles(cg, calleeFile)
	if len(got) != maxIncrementalCallers {
		t.Errorf("len(callers) = %d, want exactly the cap %d", len(got), maxIncrementalCallers)
	}
	// The result must be the deterministic sorted prefix.
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Fatalf("callers not sorted ascending at %d: %q >= %q", i, got[i-1], got[i])
		}
	}
}

// A nil graph is tolerated and returns nil.
func TestCallersOfFileFromOtherFiles_NilGraph(t *testing.T) {
	if got := CallersOfFileFromOtherFiles(nil, "x.go"); got != nil {
		t.Errorf("nil graph should yield nil, got %v", got)
	}
}
