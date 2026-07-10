package graph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// TestGoResolver_ReadGoModModulePath verifies the relaxed go.mod parser.
func TestGoResolver_ReadGoModModulePath(t *testing.T) {
	tmp := t.TempDir()
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"simple", "module example.com/foo\n\ngo 1.21\n", "example.com/foo"},
		{"quoted", "module \"example.com/foo\"\n", "example.com/foo"},
		{"with_comment", "// header\nmodule example.com/foo // trailing\n", "example.com/foo"},
		{"empty", "go 1.21\n", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(tmp, tc.name+".mod")
			if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
				t.Fatal(err)
			}
			if got := readGoModModulePath(path); got != tc.want {
				t.Errorf("readGoModModulePath = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestGoResolver_ProjectRoot walks up to find go.mod.
func TestGoResolver_ProjectRoot(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "go.mod"), []byte("module example.com/foo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(tmp, "services", "auth")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	r := &goResolver{}
	manifest, mod, ok := r.ProjectRoot(sub)
	if !ok {
		t.Fatalf("ProjectRoot did not find manifest from %q", sub)
	}
	if mod != "example.com/foo" {
		t.Errorf("ProjectRoot module = %q, want example.com/foo", mod)
	}
	if filepath.Clean(manifest) != filepath.Join(tmp, "go.mod") {
		t.Errorf("ProjectRoot manifest = %q, want %q", manifest, filepath.Join(tmp, "go.mod"))
	}
}

// TestGoResolver_ExtractScope_VariousImports covers aliased, blank, dot,
// unaliased, and quoted-path imports.
func TestGoResolver_ExtractScope_VariousImports(t *testing.T) {
	src := []byte(`package foo

import (
	"net/http"
	auth "example.com/foo/services/auth"
	. "fmt"
	_ "github.com/lib/pq"
	"example.com/foo/db"
)

func bar() {}
`)
	r := &goResolver{}
	scope, err := r.ExtractScope("foo/bar.go", src)
	if err != nil {
		t.Fatalf("ExtractScope error: %v", err)
	}
	if scope.Package != "foo" {
		t.Errorf("Package = %q, want foo", scope.Package)
	}
	want := map[string]string{
		"http": "net/http",
		"auth": "example.com/foo/services/auth",
		"db":   "example.com/foo/db",
	}
	for alias, ip := range want {
		if scope.Imports[alias] != ip {
			t.Errorf("Imports[%q] = %q, want %q", alias, scope.Imports[alias], ip)
		}
	}
	// Dot import → star imports; blank import → ignored entirely.
	if len(scope.StarImports) != 1 || scope.StarImports[0] != "fmt" {
		t.Errorf("StarImports = %v, want [fmt]", scope.StarImports)
	}
	if _, has := scope.Imports["pq"]; has {
		t.Errorf("blank import not skipped: %v", scope.Imports)
	}
}

// TestGoResolver_ResolveCall_InProject is the headline test for the
// cross-file pass on a synthetic two-file Go project. Uses absolute
// paths under the test's temp dir so relativeDir's path arithmetic
// works without needing to fudge filepath.IsAbs handling.
func TestGoResolver_ResolveCall_InProject(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")

	mkPath := func(rel string) string { return filepath.Join(root, rel) }

	// Source file: handler.go calls auth.LoginByName + db.Open + json.Marshal.
	handlerPath := mkPath("routers/handler.go")
	authPath := mkPath("services/auth/auth.go")
	dbPath := mkPath("models/db/db.go")

	cg.AddNode(&FuncNode{
		ID:       handlerPath + ":Login",
		FilePath: handlerPath,
		Name:     "Login",
		Package:  "routers",
		Language: rules.LangGo,
		RawCalls: []string{
			"auth.LoginByName",
			"db.Open",
			"json.Marshal",
		},
	})
	cg.AddNode(&FuncNode{
		ID:       authPath + ":LoginByName",
		FilePath: authPath,
		Name:     "LoginByName",
		Package:  "auth",
		Language: rules.LangGo,
	})
	cg.AddNode(&FuncNode{
		ID:       dbPath + ":Open",
		FilePath: dbPath,
		Name:     "Open",
		Package:  "db",
		Language: rules.LangGo,
	})

	contents := map[string][]byte{
		handlerPath: []byte(`package routers

import (
	"encoding/json"
	"example.com/proj/services/auth"
	"example.com/proj/models/db"
)

func Login() {}
`),
		authPath: []byte("package auth\n\nfunc LoginByName() {}\n"),
		dbPath:   []byte("package db\n\nfunc Open() {}\n"),
	}

	cg.ModulePaths = map[rules.Language]string{rules.LangGo: "example.com/proj"}
	cg.ModuleRoots = map[rules.Language]string{rules.LangGo: root}

	stats := ResolveCrossFileEdges(cg, root, contents)

	if stats.CrossFileEdges != 2 {
		t.Errorf("CrossFileEdges = %d, want 2 (stats=%+v)", stats.CrossFileEdges, stats)
	}
	if stats.ExternEdges != 1 {
		t.Errorf("ExternEdges = %d, want 1 (stats=%+v)", stats.ExternEdges, stats)
	}

	caller := cg.GetNode(handlerPath + ":Login")
	if caller == nil {
		t.Fatal("caller node missing")
	}
	wantAuth := authPath + ":LoginByName"
	wantDB := dbPath + ":Open"
	if !containsStr(caller.Calls, wantAuth) {
		t.Errorf("caller.Calls missing %q (got %v)", wantAuth, caller.Calls)
	}
	if !containsStr(caller.Calls, wantDB) {
		t.Errorf("caller.Calls missing %q (got %v)", wantDB, caller.Calls)
	}

	authNode := cg.GetNode(wantAuth)
	if authNode == nil || !containsStr(authNode.CalledBy, handlerPath+":Login") {
		t.Errorf("CalledBy back-edge missing on auth node: %+v", authNode)
	}

	if len(caller.ExternCalls) != 1 || caller.ExternCalls[0] != "encoding/json.Marshal" {
		t.Errorf("ExternCalls = %v, want [encoding/json.Marshal]", caller.ExternCalls)
	}
}

// TestResolveCrossFileEdges_Idempotent verifies running the pass twice
// produces the same result.
func TestResolveCrossFileEdges_Idempotent(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	aPath := filepath.Join(root, "a.go")
	bPath := filepath.Join(root, "b/b.go")
	cg.AddNode(&FuncNode{
		ID:       aPath + ":F",
		FilePath: aPath,
		Name:     "F",
		Language: rules.LangGo,
		RawCalls: []string{"b.G"},
	})
	cg.AddNode(&FuncNode{
		ID:       bPath + ":G",
		FilePath: bPath,
		Name:     "G",
		Language: rules.LangGo,
	})
	cg.ModulePaths = map[rules.Language]string{rules.LangGo: "example.com/proj"}
	cg.ModuleRoots = map[rules.Language]string{rules.LangGo: root}
	contents := map[string][]byte{
		aPath: []byte("package a\nimport \"example.com/proj/b\"\nfunc F() {}\n"),
		bPath: []byte("package b\nfunc G() {}\n"),
	}

	s1 := ResolveCrossFileEdges(cg, root, contents)
	s2 := ResolveCrossFileEdges(cg, root, contents)
	// First pass adds the edge; second pass observes it already exists.
	// CrossFileEdges only counts newly-added edges so second.CrossFileEdges
	// should be 0 — state, not stats, is what must remain stable.
	if s1.CrossFileEdges != 1 || s2.CrossFileEdges != 0 {
		t.Errorf("idempotency stats wrong: first=%+v second=%+v (want first.CrossFileEdges=1 second.CrossFileEdges=0)", s1, s2)
	}
	caller := cg.GetNode(aPath + ":F")
	if got := len(caller.Calls); got != 1 {
		t.Errorf("after two passes, Calls has %d entries, want 1 (got %v)", got, caller.Calls)
	}
}
