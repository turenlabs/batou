// Exact-first two-pass name resolution tests.
//
// Node IDs are "<filePath>:<funcName>" where funcName is either a bare
// top-level name ("helper") or receiver-qualified ("Cls.helper"). The
// resolvers used to return the FIRST candidate matching
// `name == fn || strings.HasSuffix(fn, "."+name)`, so a bare call could
// bind to "Cls.helper" even when a free function "helper" existed in the
// same bucket — order-dependently. Each test seeds the METHOD candidate
// FIRST so any first-hit regression flips the assertion, then checks the
// suffix fallback still fires when only the method exists.
package graph

import (
	"testing"
)

func TestGoResolveQualifiedExactFirst(t *testing.T) {
	r := &goResolver{}
	mod := "example.com/app"
	pkg := "example.com/app/util"
	scope := FileScope{
		FilePath: "/proj/main.go",
		Imports:  map[string]string{"util": pkg},
	}

	idx := NewPackageIndex()
	// Method added FIRST: first-hit suffix matching would return it.
	idx.Add(pkg, "/proj/util/u.go:Cls.helper")
	idx.Add(pkg, "/proj/util/u.go:helper")

	got := r.ResolveCall("util.helper", scope, mod, idx)
	if got.TargetID != "/proj/util/u.go:helper" {
		t.Errorf("ResolveCall(util.helper) = %q, want free function /proj/util/u.go:helper", got.TargetID)
	}

	// Suffix fallback: only the method exists.
	idx2 := NewPackageIndex()
	idx2.Add(pkg, "/proj/util/u.go:Cls.helper")
	got = r.ResolveCall("util.helper", scope, mod, idx2)
	if got.TargetID != "/proj/util/u.go:Cls.helper" {
		t.Errorf("ResolveCall(util.helper) fallback = %q, want /proj/util/u.go:Cls.helper", got.TargetID)
	}
}

func TestResolveJSNodeIDExactFirst(t *testing.T) {
	file := "/proj/src/util.js"
	idx := NewPackageIndex()
	idx.Add(file, file+":Cls.helper") // method first
	idx.Add(file, file+":helper")

	if id, ok := resolveJSNodeID(file, "helper", idx); !ok || id != file+":helper" {
		t.Errorf("resolveJSNodeID(helper) = (%q,%v), want free function", id, ok)
	}

	idx2 := NewPackageIndex()
	idx2.Add(file, file+":Cls.helper")
	if id, ok := resolveJSNodeID(file, "helper", idx2); !ok || id != file+":Cls.helper" {
		t.Errorf("resolveJSNodeID(helper) fallback = (%q,%v), want Cls.helper", id, ok)
	}
}

func TestResolvePythonNodeIDExactFirst(t *testing.T) {
	module := "app.util"
	file := "/proj/app/util.py"
	idx := NewPackageIndex()
	idx.Add(module, file+":Cls.helper") // method first
	idx.Add(module, file+":helper")

	if id, ok := resolvePythonNodeID("app.util.helper", idx); !ok || id != file+":helper" {
		t.Errorf("resolvePythonNodeID(helper) = (%q,%v), want module-level function", id, ok)
	}

	idx2 := NewPackageIndex()
	idx2.Add(module, file+":Cls.helper")
	if id, ok := resolvePythonNodeID("app.util.helper", idx2); !ok || id != file+":Cls.helper" {
		t.Errorf("resolvePythonNodeID(helper) fallback = (%q,%v), want Cls.helper", id, ok)
	}
}

func TestResolveRubyNodeIDExactFirst(t *testing.T) {
	file := "/proj/lib/util.rb"
	idx := NewPackageIndex()
	idx.Add(file, file+":Cls.helper") // method first
	idx.Add(file, file+":helper")

	// Bare call (no class qualifier): top-level def must win.
	if id, ok := resolveRubyNodeID(file, "", "helper", idx); !ok || id != file+":helper" {
		t.Errorf("resolveRubyNodeID(helper) = (%q,%v), want top-level def", id, ok)
	}
	// Qualified call still prefers the class match.
	if id, ok := resolveRubyNodeID(file, "Cls", "helper", idx); !ok || id != file+":Cls.helper" {
		t.Errorf("resolveRubyNodeID(Cls.helper) = (%q,%v), want Cls.helper", id, ok)
	}

	idx2 := NewPackageIndex()
	idx2.Add(file, file+":Cls.helper")
	if id, ok := resolveRubyNodeID(file, "", "helper", idx2); !ok || id != file+":Cls.helper" {
		t.Errorf("resolveRubyNodeID(helper) fallback = (%q,%v), want Cls.helper", id, ok)
	}
}

func TestResolveLuaNodeIDExactFirst(t *testing.T) {
	file := "/proj/src/util.lua"
	idx := NewPackageIndex()
	idx.Add(file, file+":M.helper") // module-table entry first
	idx.Add(file, file+":helper")

	if id, ok := resolveLuaNodeID(file, "m", "helper", idx); !ok || id != file+":helper" {
		t.Errorf("resolveLuaNodeID(helper) = (%q,%v), want bare function", id, ok)
	}

	idx2 := NewPackageIndex()
	idx2.Add(file, file+":M.helper")
	if id, ok := resolveLuaNodeID(file, "m", "helper", idx2); !ok || id != file+":M.helper" {
		t.Errorf("resolveLuaNodeID(helper) fallback = (%q,%v), want M.helper", id, ok)
	}
}

func TestResolveRustNodeIDExactFirst(t *testing.T) {
	file := "/proj/src/util.rs"
	idx := NewPackageIndex()
	idx.Add(file, file+":Cls.helper") // impl method first
	idx.Add(file, file+":helper")

	if id, ok := resolveRustNodeID(file, "helper", idx); !ok || id != file+":helper" {
		t.Errorf("resolveRustNodeID(helper) = (%q,%v), want free function", id, ok)
	}

	idx2 := NewPackageIndex()
	idx2.Add(file, file+":Cls.helper")
	if id, ok := resolveRustNodeID(file, "helper", idx2); !ok || id != file+":Cls.helper" {
		t.Errorf("resolveRustNodeID(helper) fallback = (%q,%v), want Cls.helper", id, ok)
	}
}

func TestResolvePerlNodeIDExactFirst(t *testing.T) {
	file := "/proj/lib/Util.pm"
	idx := NewPackageIndex()
	idx.Add(file, file+":Cls.helper") // package-qualified sub first
	idx.Add(file, file+":helper")

	if id, ok := resolvePerlNodeID(file, "helper", idx); !ok || id != file+":helper" {
		t.Errorf("resolvePerlNodeID(helper) = (%q,%v), want bare sub", id, ok)
	}

	idx2 := NewPackageIndex()
	idx2.Add(file, file+":Cls.helper")
	if id, ok := resolvePerlNodeID(file, "helper", idx2); !ok || id != file+":Cls.helper" {
		t.Errorf("resolvePerlNodeID(helper) fallback = (%q,%v), want Cls.helper", id, ok)
	}
}

func TestResolveSwiftNodeIDExactFirstAndSameDir(t *testing.T) {
	// Exact beats dotted-suffix regardless of bucket order.
	idx := NewPackageIndex()
	idx.Add(swiftModuleBucket, "/proj/a/A.swift:Cls.helper") // method first
	idx.Add(swiftModuleBucket, "/proj/b/B.swift:helper")

	if id, ok := resolveSwiftNodeID("helper", "/proj/x/C.swift", idx); !ok || id != "/proj/b/B.swift:helper" {
		t.Errorf("resolveSwiftNodeID(helper) = (%q,%v), want exact /proj/b/B.swift:helper", id, ok)
	}

	// Multiple exact matches: prefer the caller's own directory.
	idx2 := NewPackageIndex()
	idx2.Add(swiftModuleBucket, "/proj/a/A.swift:helper")
	idx2.Add(swiftModuleBucket, "/proj/b/B.swift:helper")

	if id, ok := resolveSwiftNodeID("helper", "/proj/b/C.swift", idx2); !ok || id != "/proj/b/B.swift:helper" {
		t.Errorf("resolveSwiftNodeID(helper, same-dir) = (%q,%v), want /proj/b/B.swift:helper", id, ok)
	}
	// Still ambiguous (no same-dir exact): first in bucket order.
	if id, ok := resolveSwiftNodeID("helper", "/proj/z/C.swift", idx2); !ok || id != "/proj/a/A.swift:helper" {
		t.Errorf("resolveSwiftNodeID(helper, no same-dir) = (%q,%v), want first exact /proj/a/A.swift:helper", id, ok)
	}

	// Suffix fallback: only the method exists.
	idx3 := NewPackageIndex()
	idx3.Add(swiftModuleBucket, "/proj/a/A.swift:Cls.helper")
	if id, ok := resolveSwiftNodeID("helper", "/proj/b/C.swift", idx3); !ok || id != "/proj/a/A.swift:Cls.helper" {
		t.Errorf("resolveSwiftNodeID(helper) fallback = (%q,%v), want Cls.helper", id, ok)
	}
}
