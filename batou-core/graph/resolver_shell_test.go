package graph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// TestShellResolver_Registered confirms init() wired the resolver into
// the registry.
func TestShellResolver_Registered(t *testing.T) {
	if r := GetResolver(rules.LangShell); r == nil {
		t.Fatal("Shell resolver not registered")
	}
}

// TestShellResolver_ProjectRoot_Makefile verifies the heuristic anchor
// walk finds a Makefile from a nested directory.
func TestShellResolver_ProjectRoot_Makefile(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "Makefile"), []byte("all:\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(root, "scripts")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	r := &shellResolver{}
	manifest, mod, ok := r.ProjectRoot(sub)
	if !ok {
		t.Fatalf("ProjectRoot did not find anchor from %q", sub)
	}
	if mod != "" {
		t.Errorf("modulePath = %q, want empty (Shell keys by abs file path)", mod)
	}
	if filepath.Clean(manifest) != filepath.Join(root, "Makefile") {
		t.Errorf("manifest = %q, want %q", manifest, filepath.Join(root, "Makefile"))
	}
}

// TestShellResolver_ExtractScope_SourceDirectives covers the directive
// shapes collectShellSources / shellFirstArg must handle: bare `source`,
// the `.` alias, a quoted literal, a dynamic `$var` path (skipped), and a
// nonexistent target (skipped).
func TestShellResolver_ExtractScope_SourceDirectives(t *testing.T) {
	root := t.TempDir()
	libPath := filepath.Join(root, "lib.sh")
	utilPath := filepath.Join(root, "util.sh")
	for _, p := range []string{libPath, utilPath} {
		if err := os.WriteFile(p, []byte("get_name() { echo n; }\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mainPath := filepath.Join(root, "main.sh")
	src := []byte(`#!/bin/sh
source ./lib.sh
. util.sh
source "$DIR/dyn.sh"
source ./missing.sh
`)
	r := &shellResolver{}
	scope, err := r.ExtractScope(mainPath, src)
	if err != nil {
		t.Fatalf("ExtractScope: %v", err)
	}
	if scope.Package != mainPath || scope.FilePath != mainPath {
		t.Errorf("Package/FilePath = %q/%q, want both %q", scope.Package, scope.FilePath, mainPath)
	}
	if len(scope.StarImports) != 2 {
		t.Fatalf("StarImports = %v, want exactly [lib.sh util.sh] resolved", scope.StarImports)
	}
	if !containsStr(scope.StarImports, libPath) {
		t.Errorf("StarImports missing %q (got %v)", libPath, scope.StarImports)
	}
	if !containsStr(scope.StarImports, utilPath) {
		t.Errorf("StarImports missing %q (got %v)", utilPath, scope.StarImports)
	}
}

// TestShellResolver_ExtractScope_QuotedLiteralSource: a quoted literal
// path with no `$` expansion is still static (`source "lib.sh"`), while a
// quoted path containing an expansion is dynamic and skipped — the two
// branches of shellFirstArg's string arm.
func TestShellResolver_ExtractScope_QuotedLiteralSource(t *testing.T) {
	root := t.TempDir()
	libPath := filepath.Join(root, "lib.sh")
	if err := os.WriteFile(libPath, []byte("f() { :; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mainPath := filepath.Join(root, "main.sh")
	src := []byte("source \"lib.sh\"\nsource \"${BASE}/lib.sh\"\n")

	r := &shellResolver{}
	scope, err := r.ExtractScope(mainPath, src)
	if err != nil {
		t.Fatalf("ExtractScope: %v", err)
	}
	if len(scope.StarImports) != 1 || scope.StarImports[0] != libPath {
		t.Errorf("StarImports = %v, want [%s] (quoted literal resolves, expansion skipped)",
			scope.StarImports, libPath)
	}
}

// TestShellSourceClosure covers the transitive walk and cycle handling of
// the source-graph closure.
func TestShellSourceClosure(t *testing.T) {
	sources := map[string][]string{
		"/app/a.sh": {"/app/b.sh"},
		"/app/b.sh": {"/app/c.sh", "/app/a.sh"}, // cycle back to a
	}
	closure := shellSourceClosure("/app/a.sh", sources)
	for _, want := range []string{"/app/a.sh", "/app/b.sh", "/app/c.sh"} {
		if !closure[want] {
			t.Errorf("closure missing %q (got %v)", want, closure)
		}
	}
	if len(closure) != 3 {
		t.Errorf("closure size = %d, want 3 (got %v)", len(closure), closure)
	}

	// nil source-graph: closure is just the start file.
	solo := shellSourceClosure("/app/solo.sh", nil)
	if len(solo) != 1 || !solo["/app/solo.sh"] {
		t.Errorf("nil-graph closure = %v, want {/app/solo.sh}", solo)
	}
}

// TestShellResolver_ResolveCall_ScopedToSourceGraph is the precision
// property this resolver exists for: a bare call resolves ONLY to a
// function defined in a transitively-sourced file, never to a same-named
// function in an unrelated file.
func TestShellResolver_ResolveCall_ScopedToSourceGraph(t *testing.T) {
	mainPath := "/app/main.sh"
	libPath := "/app/lib.sh"
	unrelatedPath := "/app/tools/other.sh"

	idx := NewPackageIndex()
	idx.Add(libPath, libPath+":get_name")
	idx.Add(unrelatedPath, unrelatedPath+":get_name")
	idx.shellSources = map[string][]string{mainPath: {libPath}}

	scope := FileScope{FilePath: mainPath, Package: mainPath}
	r := &shellResolver{}

	res := r.ResolveCall("get_name", scope, "", idx)
	if res.TargetID != libPath+":get_name" {
		t.Errorf("TargetID = %q, want sourced file's %q", res.TargetID, libPath+":get_name")
	}
	if res.Confidence != 0.8 {
		t.Errorf("Confidence = %v, want 0.8", res.Confidence)
	}

	// A caller that sources NOTHING must not reach either definition.
	noSourceScope := FileScope{FilePath: "/app/standalone.sh", Package: "/app/standalone.sh"}
	if res := r.ResolveCall("get_name", noSourceScope, "", idx); res != (ResolveResult{}) {
		t.Errorf("un-sourced caller resolved anyway: %+v", res)
	}

	// Built-ins / external binaries find no node — zero result.
	if res := r.ResolveCall("curl", scope, "", idx); res != (ResolveResult{}) {
		t.Errorf("external binary resolved: %+v", res)
	}
	if res := r.ResolveCall("", scope, "", idx); res != (ResolveResult{}) {
		t.Errorf("empty callee resolved: %+v", res)
	}
}

// TestShellResolver_CrossFileEdge is the end-to-end check: main.sh
// sources lib.sh and calls get_name; the cross-file pass must add a Calls
// edge to lib.sh's function node (exercising ExtractScope,
// buildShellSourceGraph, ResolveCall, and resolveShellNodeID together).
func TestShellResolver_CrossFileEdge(t *testing.T) {
	root := t.TempDir()
	mainPath := filepath.Join(root, "main.sh")
	libPath := filepath.Join(root, "lib.sh")

	mainSrc := "#!/bin/sh\nsource ./lib.sh\n\nhandle() {\n  get_name\n}\n"
	libSrc := "get_name() {\n  echo \"$USER\"\n}\n"
	if err := os.WriteFile(mainPath, []byte(mainSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(libPath, []byte(libSrc), 0o644); err != nil {
		t.Fatal(err)
	}

	cg := NewCallGraph(root, "test")
	cg.AddNode(&FuncNode{
		ID:       mainPath + ":handle",
		FilePath: mainPath,
		Name:     "handle",
		Language: rules.LangShell,
		RawCalls: []string{"get_name"},
	})
	cg.AddNode(&FuncNode{
		ID:       libPath + ":get_name",
		FilePath: libPath,
		Name:     "get_name",
		Language: rules.LangShell,
	})

	contents := map[string][]byte{
		mainPath: []byte(mainSrc),
		libPath:  []byte(libSrc),
	}
	stats := ResolveCrossFileEdges(cg, root, contents)
	if stats.CrossFileEdges < 1 {
		t.Errorf("CrossFileEdges = %d, want >= 1 (stats=%+v)", stats.CrossFileEdges, stats)
	}
	caller := cg.GetNode(mainPath + ":handle")
	wantTarget := libPath + ":get_name"
	if !containsStr(caller.Calls, wantTarget) {
		t.Errorf("caller.Calls missing %q (got %v)", wantTarget, caller.Calls)
	}
}
