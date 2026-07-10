package graph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// The goTypesResolver delegates Language / ProjectRoot / ExtractScope /
// ResolveCall to the legacy goResolver so scope extraction is identical
// regardless of which call resolver is active. These tests pin that
// delegation contract (the bulk ResolveModule path is covered by
// resolver_golang_types_test.go).

// TestGoTypesResolver_Language verifies the delegate reports Go.
func TestGoTypesResolver_Language(t *testing.T) {
	r := &goTypesResolver{}
	if got := r.Language(); got != rules.LangGo {
		t.Errorf("Language() = %v, want LangGo", got)
	}
}

// TestGoTypesResolver_ProjectRoot_Delegates: go.mod discovery through the
// delegate matches the legacy resolver (manifest path + module path).
func TestGoTypesResolver_ProjectRoot_Delegates(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"),
		[]byte("module example.com/myapp\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(root, "internal", "web")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	r := &goTypesResolver{}
	manifest, mod, ok := r.ProjectRoot(sub)
	if !ok {
		t.Fatalf("ProjectRoot did not find go.mod from %q", sub)
	}
	if mod != "example.com/myapp" {
		t.Errorf("modulePath = %q, want example.com/myapp", mod)
	}
	if filepath.Clean(manifest) != filepath.Join(root, "go.mod") {
		t.Errorf("manifest = %q, want %q", manifest, filepath.Join(root, "go.mod"))
	}
}

// TestGoTypesResolver_ExtractScope_Delegates: import parsing through the
// delegate produces the legacy alias → import-path map, including
// explicit aliases, dot imports (StarImports), and skipped blank imports.
func TestGoTypesResolver_ExtractScope_Delegates(t *testing.T) {
	src := []byte(`package web

import (
	"net/http"
	h "html/template"
	. "strings"
	_ "embed"
)
`)
	r := &goTypesResolver{}
	scope, err := r.ExtractScope("/app/handler.go", src)
	if err != nil {
		t.Fatalf("ExtractScope: %v", err)
	}
	if scope.Package != "web" {
		t.Errorf("Package = %q, want web", scope.Package)
	}
	if got := scope.Imports["http"]; got != "net/http" {
		t.Errorf("Imports[http] = %q, want net/http", got)
	}
	if got := scope.Imports["h"]; got != "html/template" {
		t.Errorf("Imports[h] = %q, want html/template", got)
	}
	if len(scope.StarImports) != 1 || scope.StarImports[0] != "strings" {
		t.Errorf("StarImports = %v, want [strings]", scope.StarImports)
	}
	if _, exists := scope.Imports["embed"]; exists {
		t.Errorf("blank import must not bind an alias; Imports = %v", scope.Imports)
	}
}

// TestGoTypesResolver_ResolveCall_Delegates: ResolveCall on the go/types
// resolver falls back to the legacy name-matching path — an in-module
// "pkg.Func" call resolves against the PackageIndex.
func TestGoTypesResolver_ResolveCall_Delegates(t *testing.T) {
	modulePath := "example.com/myapp"
	dbPkg := modulePath + "/db"
	idx := NewPackageIndex()
	idx.Add(dbPkg, "/proj/db/query.go:GetUser")

	scope := FileScope{
		FilePath: "/proj/web/handler.go",
		Package:  "web",
		Imports:  map[string]string{"db": dbPkg},
	}
	r := &goTypesResolver{}
	res := r.ResolveCall("db.GetUser", scope, modulePath, idx)
	if res.TargetID != "/proj/db/query.go:GetUser" {
		t.Errorf("TargetID = %q, want /proj/db/query.go:GetUser", res.TargetID)
	}

	// Out-of-module import path routes to extern, same as legacy.
	externScope := FileScope{
		FilePath: "/proj/web/handler.go",
		Package:  "web",
		Imports:  map[string]string{"http": "net/http"},
	}
	res = r.ResolveCall("http.Get", externScope, modulePath, idx)
	if res.TargetID != "" {
		t.Errorf("stdlib call must not resolve in-project; got %q", res.TargetID)
	}
}

// TestGoTypesResolver_RecordUnresolved covers the dedup + counter
// behavior of recordUnresolved.
func TestGoTypesResolver_RecordUnresolved(t *testing.T) {
	r := &goTypesResolver{}
	node := &FuncNode{ID: "/proj/main.go:run", Name: "run"}
	stats := &resolveModuleStats{}

	r.recordUnresolved(node, "conn.Exec", stats)
	r.recordUnresolved(node, "conn.Exec", stats) // duplicate — must not double-count
	r.recordUnresolved(node, "", stats)          // empty — no-op
	r.recordUnresolved(node, "tmpl.Render", stats)

	if len(node.UnresolvedCalls) != 2 {
		t.Errorf("UnresolvedCalls = %v, want exactly [conn.Exec tmpl.Render]", node.UnresolvedCalls)
	}
	if !containsStr(node.UnresolvedCalls, "conn.Exec") || !containsStr(node.UnresolvedCalls, "tmpl.Render") {
		t.Errorf("UnresolvedCalls = %v, missing expected entries", node.UnresolvedCalls)
	}
	if stats.Unresolved != 2 {
		t.Errorf("stats.Unresolved = %d, want 2 (dedup + empty no-op)", stats.Unresolved)
	}
}
