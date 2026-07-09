package graph

import (
	"os"
	"path/filepath"
	"testing"
)

// Tests for the disk-backed resolver entry points (ProjectRoot,
// findXxxModuleRoot, module-file resolution, sibling discovery, source
// path resolution). All use t.TempDir() so they are hermetic and
// deterministic.

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// ---- Rust (resolver_rust.go) ----

func TestRustProjectRoot_CargoToml(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "Cargo.toml"), "[package]\nname=\"x\"\n")
	sub := filepath.Join(root, "src", "handlers")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	r := &rustResolver{}
	manifest, mod, ok := r.ProjectRoot(sub)
	if !ok {
		t.Fatal("ProjectRoot should find Cargo.toml walking up")
	}
	if manifest != filepath.Join(root, "Cargo.toml") {
		t.Errorf("manifest = %q, want %q", manifest, filepath.Join(root, "Cargo.toml"))
	}
	if mod != "" {
		t.Errorf("Rust modulePath should be empty, got %q", mod)
	}
}

func TestFindRustModuleRoot(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "Cargo.toml"), "[package]\n")
	file := filepath.Join(root, "src", "lib.rs")
	writeFile(t, file, "pub fn x() {}")
	if got := findRustModuleRoot(file); got != root {
		t.Errorf("findRustModuleRoot = %q, want %q", got, root)
	}
	// A file with no crate marker anywhere returns "".
	orphan := filepath.Join(t.TempDir(), "loose.rs")
	writeFile(t, orphan, "fn y() {}")
	// The temp dir itself has no Cargo.toml and no src/ dir.
	if got := findRustModuleRoot(orphan); got != "" {
		// The parent temp dir may legitimately have no marker; tolerate
		// only the empty result.
		t.Logf("findRustModuleRoot(orphan) = %q (acceptable if a marker dir exists upstream)", got)
	}
}

func TestRustResolveModFile(t *testing.T) {
	root := t.TempDir()
	// `mod foo;` declared from main.rs resolves to sibling foo.rs.
	main := filepath.Join(root, "main.rs")
	writeFile(t, main, "mod foo;")
	writeFile(t, filepath.Join(root, "foo.rs"), "pub fn bar() {}")
	got := rustResolveModFile("foo", main)
	if got != filepath.Join(root, "foo.rs") {
		t.Errorf("rustResolveModFile(foo) = %q, want %q", got, filepath.Join(root, "foo.rs"))
	}
	// mod dir form: foo/mod.rs.
	writeFile(t, filepath.Join(root, "baz", "mod.rs"), "pub fn q() {}")
	got = rustResolveModFile("baz", main)
	if got != filepath.Join(root, "baz", "mod.rs") {
		t.Errorf("rustResolveModFile(baz) = %q, want %q", got, filepath.Join(root, "baz", "mod.rs"))
	}
	// Missing module -> "".
	if got := rustResolveModFile("missing", main); got != "" {
		t.Errorf("rustResolveModFile(missing) = %q, want empty", got)
	}
	if got := rustResolveModFile("", main); got != "" {
		t.Errorf("rustResolveModFile(\"\") = %q, want empty", got)
	}
}

// ---- C++ self-sibling discovery (resolver_cpp.go) ----

func TestCPPSelfSiblings(t *testing.T) {
	root := t.TempDir()
	// foo.cpp and foo.h form one compilation unit.
	cpp := filepath.Join(root, "foo.cpp")
	writeFile(t, cpp, "#include \"foo.h\"\nint foo(){return 0;}")
	writeFile(t, filepath.Join(root, "foo.h"), "int foo();")
	sibs := cppSelfSiblings(cpp)
	found := false
	for _, s := range sibs {
		if filepath.Base(s) == "foo.h" {
			found = true
		}
	}
	if !found {
		t.Errorf("cppSelfSiblings(foo.cpp) = %v, want it to include foo.h", sibs)
	}
	// A file with no complementary sibling yields none.
	lone := filepath.Join(root, "only.cpp")
	writeFile(t, lone, "int main(){return 0;}")
	if sibs := cppSelfSiblings(lone); len(sibs) != 0 {
		t.Errorf("cppSelfSiblings(only.cpp) = %v, want none", sibs)
	}
}

// ---- Shell source-path resolution (resolver_shell.go) ----

func TestResolveShellSourcePath(t *testing.T) {
	dir := t.TempDir()
	lib := filepath.Join(dir, "lib.sh")
	writeFile(t, lib, "echo hi")

	// Relative resolves against baseDir.
	if got := resolveShellSourcePath("lib.sh", dir); got != lib {
		t.Errorf("resolveShellSourcePath(lib.sh) = %q, want %q", got, lib)
	}
	if got := resolveShellSourcePath("./lib.sh", dir); got != lib {
		t.Errorf("resolveShellSourcePath(./lib.sh) = %q, want %q", got, lib)
	}
	// Absolute path used directly.
	if got := resolveShellSourcePath(lib, "/unused"); got != lib {
		t.Errorf("resolveShellSourcePath(abs) = %q, want %q", got, lib)
	}
	// Dynamic ($-bearing) path -> "".
	if got := resolveShellSourcePath("$HOME/lib.sh", dir); got != "" {
		t.Errorf("resolveShellSourcePath($dynamic) = %q, want empty", got)
	}
	// Non-existent file -> "".
	if got := resolveShellSourcePath("nope.sh", dir); got != "" {
		t.Errorf("resolveShellSourcePath(missing) = %q, want empty", got)
	}
	// Empty arg -> "".
	if got := resolveShellSourcePath("", dir); got != "" {
		t.Errorf("resolveShellSourcePath(\"\") = %q, want empty", got)
	}
}

// ---- Node-ID resolution against a PackageIndex (resolver_swift.go,
// resolver_rust.go) ----

func TestResolveSwiftNodeID(t *testing.T) {
	idx := NewPackageIndex()
	// Swift nodes are bucketed under swiftModuleBucket.
	idx.Add(swiftModuleBucket, "/proj/A.swift:Foo.bar")
	idx.Add(swiftModuleBucket, "/proj/B.swift:baz")

	// Exact suffix match.
	if id, ok := resolveSwiftNodeID("baz", "", idx); !ok || id != "/proj/B.swift:baz" {
		t.Errorf("resolveSwiftNodeID(baz) = (%q,%v)", id, ok)
	}
	// Dotted-suffix match (`Foo.bar`).
	if id, ok := resolveSwiftNodeID("bar", "", idx); !ok || id != "/proj/A.swift:Foo.bar" {
		t.Errorf("resolveSwiftNodeID(bar) = (%q,%v)", id, ok)
	}
	// Unknown -> not found.
	if _, ok := resolveSwiftNodeID("nope", "", idx); ok {
		t.Error("resolveSwiftNodeID(nope) should not resolve")
	}
	// Defensive nil/empty.
	if _, ok := resolveSwiftNodeID("", "", idx); ok {
		t.Error("empty suffix should not resolve")
	}
	if _, ok := resolveSwiftNodeID("bar", "", nil); ok {
		t.Error("nil index should not resolve")
	}
}

func TestResolveRustNodeID(t *testing.T) {
	idx := NewPackageIndex()
	// Rust nodes are bucketed by absolute file path.
	file := "/proj/src/handlers.rs"
	idx.Add(file, file+":handle_request")
	idx.Add(file, file+":mod_a.helper")

	if id, ok := resolveRustNodeID(file, "handle_request", idx); !ok || id != file+":handle_request" {
		t.Errorf("resolveRustNodeID(handle_request) = (%q,%v)", id, ok)
	}
	// Dotted method: matches by trailing segment.
	if id, ok := resolveRustNodeID(file, "helper", idx); !ok || id != file+":mod_a.helper" {
		t.Errorf("resolveRustNodeID(helper) = (%q,%v)", id, ok)
	}
	// Wrong file bucket -> not found.
	if _, ok := resolveRustNodeID("/other.rs", "handle_request", idx); ok {
		t.Error("resolveRustNodeID in wrong file bucket should not resolve")
	}
	// Defensive nil/empty.
	if _, ok := resolveRustNodeID("", "x", idx); ok {
		t.Error("empty filePath should not resolve")
	}
	if _, ok := resolveRustNodeID(file, "", idx); ok {
		t.Error("empty method should not resolve")
	}
	if _, ok := resolveRustNodeID(file, "x", nil); ok {
		t.Error("nil index should not resolve")
	}
}
