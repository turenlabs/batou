package graph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// The C/C++ cross-file RESOLVER (resolver_cpp.go) resolves #include directives
// to sibling in-project files and resolves a cross-file C/C++ call to a callee
// FuncNode in an included translation unit. It is the live path GetResolver
// returns for rules.LangC / rules.LangCPP, but had ZERO graph-package unit
// coverage. These tests exercise cppGrammarForPath, ProjectRoot, ExtractScope
// (#include parsing via collectCPPIncludes/cppStripIncludeLiteral +
// resolveCPPInclude), cppIncludeTargets, and ResolveCall (via a constructed
// PackageIndex).

func TestCPPResolver_Registered(t *testing.T) {
	if GetResolver(rules.LangCPP) == nil {
		t.Error("no resolver registered for LangCPP")
	}
	if GetResolver(rules.LangC) == nil {
		t.Error("no resolver registered for LangC")
	}
}

func TestCPPResolver_GrammarForPath(t *testing.T) {
	cases := map[string]rules.Language{
		"/p/a.c":    rules.LangC,   // only an unambiguous .c selects the C grammar
		"/p/a.cpp":  rules.LangCPP,
		"/p/a.cc":   rules.LangCPP,
		"/p/a.cxx":  rules.LangCPP,
		"/p/a.h":    rules.LangCPP, // ambiguous header -> C++ (superset)
		"/p/a.hpp":  rules.LangCPP,
		"/p/A.C":    rules.LangC,   // case-insensitive ext
	}
	for path, want := range cases {
		if got := cppGrammarForPath(path); got != want {
			t.Errorf("cppGrammarForPath(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestCPPResolver_ProjectRoot_CMakeManifest(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "CMakeLists.txt"), []byte("project(x)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(root, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	r := &cppResolver{lang: rules.LangCPP}
	manifest, modulePath, ok := r.ProjectRoot(src)
	if !ok {
		t.Fatal("ProjectRoot should find the CMakeLists.txt ancestor")
	}
	if modulePath != "" {
		t.Errorf("C++ modulePath should always be empty, got %q", modulePath)
	}
	if manifest == "" {
		t.Error("ProjectRoot manifest path should be non-empty")
	}
}

func TestCPPResolver_ResolveInclude(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(src, "helper.h")
	if err := os.WriteFile(helper, []byte("std::string getName();\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	main := filepath.Join(src, "main.cpp")
	got := resolveCPPInclude("helper.h", main, root)
	helperAbs, _ := filepath.Abs(helper)
	found := false
	for _, g := range got {
		if g == helperAbs {
			found = true
		}
	}
	if !found {
		t.Errorf("resolveCPPInclude(helper.h) = %v, want to contain %q", got, helperAbs)
	}
	// A non-existent include resolves to nothing.
	if g := resolveCPPInclude("does_not_exist.h", main, root); len(g) != 0 {
		t.Errorf("resolveCPPInclude(missing) = %v, want empty", g)
	}
}

func TestCPPResolver_ExtractScope_QuotedInclude(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "CMakeLists.txt"), []byte("project(x)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(src, "helper.h")
	if err := os.WriteFile(helper, []byte("std::string getName();\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mainPath := filepath.Join(src, "main.cpp")
	content := []byte("#include \"helper.h\"\n#include <vector>\nvoid handle() { getName(); }\n")
	if err := os.WriteFile(mainPath, content, 0o644); err != nil {
		t.Fatal(err)
	}

	r := &cppResolver{lang: rules.LangCPP}
	scope, err := r.ExtractScope(mainPath, content)
	if err != nil {
		t.Fatalf("ExtractScope: %v", err)
	}
	helperAbs, _ := filepath.Abs(helper)
	if scope.Imports[helperAbs] != helperAbs {
		t.Errorf("ExtractScope Imports missing the quoted include %q; got %v", helperAbs, scope.Imports)
	}
	// The <vector> system include must NOT be recorded (external library).
	for k := range scope.Imports {
		if filepath.Base(k) == "vector" {
			t.Errorf("system include <vector> should not be in scope.Imports; got %v", scope.Imports)
		}
	}
	if scope.Aux["includes"] == "" {
		t.Error("scope.Aux[includes] should be populated")
	}
	// cppIncludeTargets reads Aux[includes] and returns the resolved targets.
	targets := cppIncludeTargets(scope)
	hit := false
	for _, tg := range targets {
		if tg == helperAbs {
			hit = true
		}
	}
	if !hit {
		t.Errorf("cppIncludeTargets = %v, want to contain %q", targets, helperAbs)
	}
}

// TestCPPResolver_ResolveCall_AcrossInclude: a bare/qualified call resolves to a
// FuncNode in an included file via the PackageIndex (keyed by absolute path).
func TestCPPResolver_ResolveCall_AcrossInclude(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(src, "helper.h")
	if err := os.WriteFile(helper, []byte("std::string getName();\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mainPath := filepath.Join(src, "main.cpp")
	content := []byte("#include \"helper.h\"\nvoid handle() { getName(); }\n")
	r := &cppResolver{lang: rules.LangCPP}
	scope, err := r.ExtractScope(mainPath, content)
	if err != nil {
		t.Fatalf("ExtractScope: %v", err)
	}
	helperAbs, _ := filepath.Abs(helper)
	wantID := helperAbs + ":getName"
	idx := &PackageIndex{
		PackageToNodes: map[string][]string{helperAbs: {wantID}},
	}

	// Bare call resolves across the include.
	if res := r.ResolveCall("getName", scope, "", idx); res.TargetID != wantID {
		t.Errorf("ResolveCall(getName) TargetID = %q, want %q", res.TargetID, wantID)
	}
	// Namespace-qualified call uses the trailing suffix.
	if res := r.ResolveCall("ns::getName", scope, "", idx); res.TargetID != wantID {
		t.Errorf("ResolveCall(ns::getName) TargetID = %q, want %q", res.TargetID, wantID)
	}
	// nil index and empty callee return an empty result (no panic).
	if res := r.ResolveCall("getName", scope, "", nil); res.TargetID != "" {
		t.Errorf("ResolveCall with nil idx should be empty, got %q", res.TargetID)
	}
	if res := r.ResolveCall("", scope, "", idx); res.TargetID != "" {
		t.Errorf("ResolveCall with empty callee should be empty, got %q", res.TargetID)
	}
	// An unknown callee does not resolve.
	if res := r.ResolveCall("noSuchFunc", scope, "", idx); res.TargetID != "" {
		t.Errorf("ResolveCall(noSuchFunc) should be empty, got %q", res.TargetID)
	}
}
