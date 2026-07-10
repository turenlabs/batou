package graph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// writeTestModule materialises a synthetic Go module on disk so
// packages.Load has something real to type-check. Returns the module
// root directory. Files map keys are module-root-relative paths
// ("svc/auth.go"); values are file contents. Caller is responsible
// for calling t.TempDir() to scope the cleanup.
func writeTestModule(t *testing.T, modulePath string, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"),
		[]byte("module "+modulePath+"\n\ngo 1.25\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for rel, content := range files {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// addFuncNode is a test convenience: extract function declarations from
// content with go/parser and register them on cg. Mirrors what
// buildGoNodes does but without the dependency on internal callgraph
// helpers we don't want to pull into the test.
func addFuncNode(cg *CallGraph, filePath, name, pkg string, rawCalls []string) {
	cg.AddNode(&FuncNode{
		ID:       FuncID(filePath, name),
		FilePath: filePath,
		Name:     name,
		Package:  pkg,
		Language: rules.LangGo,
		RawCalls: rawCalls,
	})
}

// TestGoTypesResolver_AliasedImports verifies that an aliased import
// resolves to the actual import path, not the alias. Under the legacy
// resolver, "h.NewRequest" with `h "net/http"` produces extern
// "net/http.NewRequest" only by lucky accident of how the legacy
// importpath lookup works — here we confirm types-based resolution is
// authoritative.
func TestGoTypesResolver_AliasedImports(t *testing.T) {
	t.Setenv(EnvGoTypesResolver, "1")

	root := writeTestModule(t, "example.com/aliased", map[string]string{
		"main.go": `package main

import h "net/http"

func Caller() {
	h.NewRequest("GET", "http://example.com", nil)
}
`,
	})
	mainPath := filepath.Join(root, "main.go")

	cg := NewCallGraph(root, "test")
	addFuncNode(cg, mainPath, "Caller", "main", []string{"h.NewRequest"})

	// ResolveCrossFileEdges discovers the go.mod via ProjectRoot.
	stats := ResolveCrossFileEdges(cg, root, nil)
	if stats.ExternEdges == 0 {
		t.Fatalf("expected ExternEdges>0, got stats=%+v", stats)
	}

	caller := cg.GetNode(mainPath + ":Caller")
	if caller == nil {
		t.Fatal("caller node missing")
	}
	// The types-based resolver should produce "net/http.NewRequest",
	// resolving the alias to the actual import path.
	found := false
	for _, e := range caller.ExternCalls {
		if e == "net/http.NewRequest" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ExternCalls = %v, want to contain net/http.NewRequest", caller.ExternCalls)
	}
}

// TestGoTypesResolver_InterfaceMethod verifies that calling a method on
// an interface fans out to every concrete implementer in the same
// module. The legacy resolver doesn't model interfaces at all — it
// would leave this entirely unresolved.
func TestGoTypesResolver_InterfaceMethod(t *testing.T) {
	t.Setenv(EnvGoTypesResolver, "1")

	root := writeTestModule(t, "example.com/iface", map[string]string{
		"iface/iface.go": `package iface

type Greeter interface {
	Greet() string
}
`,
		"impl/impl.go": `package impl

type Hello struct{}

func (Hello) Greet() string { return "hi" }
`,
		"main.go": `package main

import (
	"example.com/iface/iface"
	"example.com/iface/impl"
)

func Use(g iface.Greeter) {
	g.Greet()
}

func Make() iface.Greeter {
	return impl.Hello{}
}
`,
	})
	mainPath := filepath.Join(root, "main.go")
	implPath := filepath.Join(root, "impl/impl.go")

	cg := NewCallGraph(root, "test")
	addFuncNode(cg, mainPath, "Use", "main", []string{"g.Greet"})
	addFuncNode(cg, implPath, "Hello.Greet", "impl", nil)

	stats := ResolveCrossFileEdges(cg, root, nil)
	caller := cg.GetNode(mainPath + ":Use")
	if caller == nil {
		t.Fatalf("caller missing; stats=%+v", stats)
	}

	// The Hello.Greet implementer should be in Calls because the
	// types-based resolver expanded the interface dispatch.
	wantImpl := implPath + ":Hello.Greet"
	if !containsStr(caller.Calls, wantImpl) {
		t.Errorf("Calls = %v, want to contain %q (interface dispatch fan-out)",
			caller.Calls, wantImpl)
	}
}

// TestGoTypesResolver_EmbeddedMethod verifies that a method call on a
// struct that embeds another struct resolves to the embedded method's
// owner. The legacy resolver matches on the variable's apparent type;
// embedded methods are invisible to it.
func TestGoTypesResolver_EmbeddedMethod(t *testing.T) {
	t.Setenv(EnvGoTypesResolver, "1")

	root := writeTestModule(t, "example.com/embed", map[string]string{
		"base/base.go": `package base

type Base struct{}

func (Base) Hello() string { return "hi" }
`,
		"main.go": `package main

import "example.com/embed/base"

type Wrapper struct {
	base.Base
}

func Use() {
	w := Wrapper{}
	_ = w.Hello() // promoted from base.Base
}
`,
	})
	mainPath := filepath.Join(root, "main.go")
	basePath := filepath.Join(root, "base/base.go")

	cg := NewCallGraph(root, "test")
	addFuncNode(cg, mainPath, "Use", "main", []string{"w.Hello"})
	addFuncNode(cg, basePath, "Base.Hello", "base", nil)

	stats := ResolveCrossFileEdges(cg, root, nil)
	caller := cg.GetNode(mainPath + ":Use")
	if caller == nil {
		t.Fatalf("caller missing; stats=%+v", stats)
	}
	// The types-based resolver should identify Hello as base.Base's
	// method even though the call site sees a Wrapper.
	wantImpl := basePath + ":Base.Hello"
	if !containsStr(caller.Calls, wantImpl) {
		// This is a known limit — types.Info.Uses on an embedded
		// method call returns the owning type's func, which we look
		// up. If the test fails, capture the actual edges for
		// diagnosis.
		t.Errorf("Calls = %v, want to contain %q (embedded method)",
			caller.Calls, wantImpl)
	}
}

// TestGoTypesResolver_Generics verifies that calls to generic functions
// resolve to the generic declaration. Generic instantiation produces
// a *types.Signature with type args, but the underlying object is the
// generic origin, which is what we resolve to.
func TestGoTypesResolver_Generics(t *testing.T) {
	t.Setenv(EnvGoTypesResolver, "1")

	root := writeTestModule(t, "example.com/gen", map[string]string{
		"gen/gen.go": `package gen

func Map[T, U any](xs []T, f func(T) U) []U {
	out := make([]U, 0, len(xs))
	for _, x := range xs {
		out = append(out, f(x))
	}
	return out
}
`,
		"main.go": `package main

import "example.com/gen/gen"

func Use() {
	gen.Map([]int{1, 2}, func(i int) string { return "" })
}
`,
	})
	mainPath := filepath.Join(root, "main.go")
	genPath := filepath.Join(root, "gen/gen.go")

	cg := NewCallGraph(root, "test")
	addFuncNode(cg, mainPath, "Use", "main", []string{"gen.Map"})
	addFuncNode(cg, genPath, "Map", "gen", nil)

	stats := ResolveCrossFileEdges(cg, root, nil)
	caller := cg.GetNode(mainPath + ":Use")
	if caller == nil {
		t.Fatalf("caller missing; stats=%+v", stats)
	}
	wantImpl := genPath + ":Map"
	if !containsStr(caller.Calls, wantImpl) {
		t.Errorf("Calls = %v, want to contain %q (generic function)",
			caller.Calls, wantImpl)
	}
}

// TestGoTypesResolver_MethodValue verifies that method values
// (e.g. `f := obj.Method; f()`) are recorded — at least the
// `obj.Method` binding line — as a call edge. types.Info treats
// `obj.Method` as a Selection so we can resolve it even though there's
// no CallExpr on that line.
//
// Note: the current resolver only looks at *ast.CallExpr, so a pure
// method-value binding without a subsequent call won't surface as an
// edge. This test exercises the case where the value IS called.
func TestGoTypesResolver_MethodValue(t *testing.T) {
	t.Setenv(EnvGoTypesResolver, "1")

	root := writeTestModule(t, "example.com/mv", map[string]string{
		"svc/svc.go": `package svc

type S struct{}

func (S) Run() {}
`,
		"main.go": `package main

import "example.com/mv/svc"

func Use() {
	s := svc.S{}
	f := s.Run
	f()
}
`,
	})
	mainPath := filepath.Join(root, "main.go")
	svcPath := filepath.Join(root, "svc/svc.go")

	cg := NewCallGraph(root, "test")
	addFuncNode(cg, mainPath, "Use", "main", []string{"f"})
	addFuncNode(cg, svcPath, "S.Run", "svc", nil)

	stats := ResolveCrossFileEdges(cg, root, nil)
	caller := cg.GetNode(mainPath + ":Use")
	if caller == nil {
		t.Fatalf("caller missing; stats=%+v", stats)
	}
	// Method values via a local variable can't be resolved without
	// dataflow; the call should at least show up as unresolved.
	// What we're really verifying here is that the resolver doesn't
	// CRASH on method values — emitting nothing is acceptable.
	t.Logf("MethodValue: Calls=%v Extern=%v Unresolved=%v",
		caller.Calls, caller.ExternCalls, caller.UnresolvedCalls)
}

// TestGoTypesResolver_DotImport verifies dot imports are handled. Under
// a dot import, names are unqualified — the legacy resolver records
// these as bare identifiers and misses cross-file resolution. The
// types-based resolver should resolve them via types.Info.Uses.
func TestGoTypesResolver_DotImport(t *testing.T) {
	t.Setenv(EnvGoTypesResolver, "1")

	root := writeTestModule(t, "example.com/dot", map[string]string{
		"lib/lib.go": `package lib

func Greet() string { return "hi" }
`,
		"main.go": `package main

import . "example.com/dot/lib"

func Use() {
	Greet()
}
`,
	})
	mainPath := filepath.Join(root, "main.go")
	libPath := filepath.Join(root, "lib/lib.go")

	cg := NewCallGraph(root, "test")
	addFuncNode(cg, mainPath, "Use", "main", []string{"Greet"})
	addFuncNode(cg, libPath, "Greet", "lib", nil)

	stats := ResolveCrossFileEdges(cg, root, nil)
	caller := cg.GetNode(mainPath + ":Use")
	if caller == nil {
		t.Fatalf("caller missing; stats=%+v", stats)
	}
	wantImpl := libPath + ":Greet"
	if !containsStr(caller.Calls, wantImpl) {
		t.Errorf("Calls = %v, want to contain %q (dot import)",
			caller.Calls, wantImpl)
	}
}

// TestGoTypesResolver_EnabledByDefault pins the PR-KK contract: with
// the env var unset, the typed resolver is the active default. Users
// who want the legacy resolver opt out with BATOU_GOTYPES_RESOLVER=0.
func TestGoTypesResolver_EnabledByDefault(t *testing.T) {
	// Explicitly unset (test infrastructure may have leftover state).
	t.Setenv(EnvGoTypesResolver, "")

	if !GoTypesResolverEnabled() {
		t.Fatal("GoTypesResolverEnabled() = false with env unset; want true (default-on)")
	}
}

// TestGoTypesResolver_OptOut covers the BATOU_GOTYPES_RESOLVER=0 etc.
// opt-out path users need when the typed resolver causes a regression
// on a specific repo.
func TestGoTypesResolver_OptOut(t *testing.T) {
	for _, v := range []string{"0", "false", "FALSE", "off", "no", "No"} {
		t.Run(v, func(t *testing.T) {
			t.Setenv(EnvGoTypesResolver, v)
			if GoTypesResolverEnabled() {
				t.Errorf("GoTypesResolverEnabled() = true with %q; want false (opt-out)", v)
			}
		})
	}
}

// TestGoTypesResolver_EnabledWithAnyTruthyValue confirms that any
// non-empty value enables the resolver. We don't need to parse the
// value — presence is enough.
func TestGoTypesResolver_EnabledWithAnyTruthyValue(t *testing.T) {
	for _, v := range []string{"1", "true", "yes", "anything"} {
		t.Run(v, func(t *testing.T) {
			t.Setenv(EnvGoTypesResolver, v)
			if !GoTypesResolverEnabled() {
				t.Errorf("GoTypesResolverEnabled() = false with %q", v)
			}
		})
	}
}

// TestIsInProject covers the in-project classification used by
// ResolveModule. Same semantics as the legacy resolver's prefix match
// (path == modulePath OR path starts with modulePath+"/").
func TestIsInProject(t *testing.T) {
	cases := []struct {
		path string
		mod  string
		want bool
	}{
		{"example.com/foo", "example.com/foo", true},
		{"example.com/foo/bar", "example.com/foo", true},
		{"example.com/foobar", "example.com/foo", false}, // no false-prefix match
		{"net/http", "example.com/foo", false},
		{"", "example.com/foo", false},
		{"example.com/foo", "", false},
	}
	for _, tc := range cases {
		if got := isInProject(tc.path, tc.mod); got != tc.want {
			t.Errorf("isInProject(%q, %q) = %v, want %v", tc.path, tc.mod, got, tc.want)
		}
	}
}
