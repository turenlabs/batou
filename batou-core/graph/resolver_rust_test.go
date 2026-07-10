package graph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// writeRustCrate lays down a minimal crate on disk:
//
//	root/Cargo.toml
//	root/src/main.rs
//	root/src/a.rs
//
// and returns (root, abs main.rs, abs a.rs). ExtractScope stats real
// files when resolving `mod a;`, so the layout must exist.
func writeRustCrate(t *testing.T, mainSrc, aSrc string) (string, string, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "Cargo.toml"),
		[]byte("[package]\nname = \"app\"\nversion = \"0.1.0\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	srcDir := filepath.Join(root, "src")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	mainPath := filepath.Join(srcDir, "main.rs")
	aPath := filepath.Join(srcDir, "a.rs")
	if err := os.WriteFile(mainPath, []byte(mainSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(aPath, []byte(aSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	return root, mainPath, aPath
}

// TestRustResolver_Registered confirms init() wired the resolver into
// the registry.
func TestRustResolver_Registered(t *testing.T) {
	if r := GetResolver(rules.LangRust); r == nil {
		t.Fatal("Rust resolver not registered")
	}
}

// TestRustResolver_ExtractScope_ModAndUse covers the two binding shapes:
// `mod a;` maps the child-module alias to src/a.rs, and `use a::get_name;`
// flattens the imported symbol onto the same file so a BARE call
// `get_name(...)` resolves. Extern paths (`use std::...`) record nothing.
func TestRustResolver_ExtractScope_ModAndUse(t *testing.T) {
	mainSrc := `mod a;
use a::get_name;
use std::io::Read;

fn main() {
    let n = get_name();
    a::other(&n);
}
`
	aSrc := "pub fn get_name() -> String { std::env::args().nth(1).unwrap() }\npub fn other(_: &str) {}\n"
	_, mainPath, aPath := writeRustCrate(t, mainSrc, aSrc)

	r := &rustResolver{}
	scope, err := r.ExtractScope(mainPath, []byte(mainSrc))
	if err != nil {
		t.Fatalf("ExtractScope: %v", err)
	}
	if scope.Package != mainPath {
		t.Errorf("Package = %q, want file's own abs path %q", scope.Package, mainPath)
	}
	if got := scope.Imports["a"]; got != aPath {
		t.Errorf("Imports[a] = %q, want %q (mod binding)", got, aPath)
	}
	if got := scope.Imports["get_name"]; got != aPath {
		t.Errorf("Imports[get_name] = %q, want %q (use-flattened binding)", got, aPath)
	}
	if got, exists := scope.Imports["Read"]; exists {
		t.Errorf("Imports[Read] = %q, want no binding (std extern is skipped)", got)
	}
}

// TestRustResolver_ExtractScope_UseWithoutMod: a `use a::sym;` with no
// preceding `mod a;` still binds when a.rs exists next to the importing
// file (collectRustUseBinding's on-disk fallback).
func TestRustResolver_ExtractScope_UseWithoutMod(t *testing.T) {
	mainSrc := "use a::get_name;\n\nfn main() { get_name(); }\n"
	aSrc := "pub fn get_name() -> String { String::new() }\n"
	_, mainPath, aPath := writeRustCrate(t, mainSrc, aSrc)

	r := &rustResolver{}
	scope, err := r.ExtractScope(mainPath, []byte(mainSrc))
	if err != nil {
		t.Fatalf("ExtractScope: %v", err)
	}
	if got := scope.Imports["get_name"]; got != aPath {
		t.Errorf("Imports[get_name] = %q, want %q", got, aPath)
	}
}

// TestRustResolver_ResolveCall_Bare: the use-flattened shape
// `use a::get_name; get_name()` resolves the bare callee through the
// import binding to the function node in a.rs.
func TestRustResolver_ResolveCall_Bare(t *testing.T) {
	aPath := "/proj/src/a.rs"
	idx := NewPackageIndex()
	idx.Add(aPath, aPath+":get_name")

	scope := FileScope{
		FilePath: "/proj/src/main.rs",
		Imports:  map[string]string{"get_name": aPath},
	}
	r := &rustResolver{}
	res := r.ResolveCall("get_name", scope, "", idx)
	if res.TargetID != aPath+":get_name" {
		t.Errorf("TargetID = %q, want %q", res.TargetID, aPath+":get_name")
	}
	if res.Confidence != 0.75 {
		t.Errorf("Confidence = %v, want 0.75", res.Confidence)
	}
}

// TestRustResolver_ResolveCall_Qualified: `a::other(...)` (normalised to
// "a.other") resolves via the `mod a;` alias, including the impl-method
// suffix match ("Type.other").
func TestRustResolver_ResolveCall_Qualified(t *testing.T) {
	aPath := "/proj/src/a.rs"

	t.Run("free function", func(t *testing.T) {
		idx := NewPackageIndex()
		idx.Add(aPath, aPath+":other")
		scope := FileScope{Imports: map[string]string{"a": aPath}}
		r := &rustResolver{}
		res := r.ResolveCall("a.other", scope, "", idx)
		if res.TargetID != aPath+":other" {
			t.Errorf("TargetID = %q, want %q", res.TargetID, aPath+":other")
		}
		if res.Confidence != 0.85 {
			t.Errorf("Confidence = %v, want 0.85", res.Confidence)
		}
	})

	t.Run("impl method suffix", func(t *testing.T) {
		idx := NewPackageIndex()
		idx.Add(aPath, aPath+":Service.run")
		scope := FileScope{Imports: map[string]string{"a": aPath}}
		r := &rustResolver{}
		res := r.ResolveCall("a.run", scope, "", idx)
		if res.TargetID != aPath+":Service.run" {
			t.Errorf("TargetID = %q, want impl-method node %q", res.TargetID, aPath+":Service.run")
		}
	})
}

// TestRustResolver_ResolveCall_ExternAndNoOpinion: a non-absolute import
// target routes to Extern; unknown aliases and missing functions yield
// the zero result.
func TestRustResolver_ResolveCall_ExternAndNoOpinion(t *testing.T) {
	aPath := "/proj/src/a.rs"
	idx := NewPackageIndex()
	idx.Add(aPath, aPath+":get_name")

	r := &rustResolver{}

	externScope := FileScope{Imports: map[string]string{"serde_json": "serde_json"}}
	res := r.ResolveCall("serde_json.from_str", externScope, "", idx)
	if res.Extern != "serde_json::from_str" {
		t.Errorf("Extern = %q, want serde_json::from_str", res.Extern)
	}
	if res.TargetID != "" {
		t.Errorf("extern call must not have TargetID; got %q", res.TargetID)
	}

	scope := FileScope{Imports: map[string]string{"a": aPath}}
	if res := r.ResolveCall("", scope, "", idx); res != (ResolveResult{}) {
		t.Errorf("empty callee: got %+v, want zero", res)
	}
	if res := r.ResolveCall("unknown.run", scope, "", idx); res != (ResolveResult{}) {
		t.Errorf("unknown alias: got %+v, want zero", res)
	}
	if res := r.ResolveCall("a.no_such_fn", scope, "", idx); res != (ResolveResult{}) {
		t.Errorf("missing fn in bound file: got %+v, want zero (no opinion)", res)
	}
}

// TestRustResolver_CrossFileEdge is the end-to-end check: main.rs declares
// `mod a;` + `use a::get_name;` and calls get_name() bare; the cross-file
// pass must add a Calls edge to the function node in src/a.rs.
func TestRustResolver_CrossFileEdge(t *testing.T) {
	mainSrc := "mod a;\nuse a::get_name;\n\nfn handler() {\n    let n = get_name();\n    let _ = n;\n}\n"
	aSrc := "pub fn get_name() -> String { std::env::args().nth(1).unwrap_or_default() }\n"
	root, mainPath, aPath := writeRustCrate(t, mainSrc, aSrc)

	cg := NewCallGraph(root, "test")
	cg.AddNode(&FuncNode{
		ID:       mainPath + ":handler",
		FilePath: mainPath,
		Name:     "handler",
		Language: rules.LangRust,
		RawCalls: []string{"get_name"},
	})
	cg.AddNode(&FuncNode{
		ID:       aPath + ":get_name",
		FilePath: aPath,
		Name:     "get_name",
		Language: rules.LangRust,
	})

	contents := map[string][]byte{
		mainPath: []byte(mainSrc),
		aPath:    []byte(aSrc),
	}
	stats := ResolveCrossFileEdges(cg, root, contents)
	if stats.CrossFileEdges < 1 {
		t.Errorf("CrossFileEdges = %d, want >= 1 (stats=%+v)", stats.CrossFileEdges, stats)
	}
	caller := cg.GetNode(mainPath + ":handler")
	wantTarget := aPath + ":get_name"
	if !containsStr(caller.Calls, wantTarget) {
		t.Errorf("caller.Calls missing %q (got %v)", wantTarget, caller.Calls)
	}
}
