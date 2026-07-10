package graph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// TestJavaResolver_Registered confirms init() wired the Java resolver
// into the registry.
func TestJavaResolver_Registered(t *testing.T) {
	if GetResolver(rules.LangJava) == nil {
		t.Fatal("Java resolver not registered")
	}
}

// TestJavaResolver_ProjectRoot_MavenLayout exercises the canonical
// Maven src/main/java layout: a pom.xml sibling to src/main/java/
// should anchor ModuleRoot at <root>/src/main/java.
func TestJavaResolver_ProjectRoot_MavenLayout(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "pom.xml"),
		[]byte(`<project></project>`), 0o644); err != nil {
		t.Fatal(err)
	}
	srcDir := filepath.Join(tmp, "src", "main", "java", "com", "example")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	r := &javaResolver{}
	manifest, mod, ok := r.ProjectRoot(srcDir)
	if !ok {
		t.Fatalf("ProjectRoot did not find manifest from %q", srcDir)
	}
	if mod != "" {
		t.Errorf("ProjectRoot module = %q, want empty (Java has no global module prefix)", mod)
	}
	// manifest should sit inside src/main/java so filepath.Dir gives
	// that as the module root.
	wantDir := filepath.Join(tmp, "src", "main", "java")
	if filepath.Dir(manifest) != wantDir {
		t.Errorf("filepath.Dir(manifest) = %q, want %q", filepath.Dir(manifest), wantDir)
	}
}

// TestJavaResolver_ProjectRoot_GradleLayout: build.gradle with the
// Maven layout should anchor the same way.
func TestJavaResolver_ProjectRoot_GradleLayout(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "build.gradle"),
		[]byte(`plugins { id 'java' }`), 0o644); err != nil {
		t.Fatal(err)
	}
	srcDir := filepath.Join(tmp, "src", "main", "java")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	r := &javaResolver{}
	manifest, _, ok := r.ProjectRoot(tmp)
	if !ok {
		t.Fatal("ProjectRoot did not return ok")
	}
	if filepath.Dir(manifest) != srcDir {
		t.Errorf("filepath.Dir(manifest) = %q, want %q", filepath.Dir(manifest), srcDir)
	}
}

// TestJavaResolver_ProjectRoot_NoManifest: scripts-only repo (no
// pom/build.gradle, no src/main/java) still returns ok=true so the
// resolver can anchor somewhere.
func TestJavaResolver_ProjectRoot_NoManifest(t *testing.T) {
	tmp := t.TempDir()
	r := &javaResolver{}
	_, _, ok := r.ProjectRoot(tmp)
	if !ok {
		t.Fatal("ProjectRoot should return ok=true even without manifests")
	}
}

// TestJavaResolver_ExtractScope_Imports verifies that import statements
// bind short class names → absolute file paths when the file exists.
func TestJavaResolver_ExtractScope_Imports(t *testing.T) {
	tmp := t.TempDir()
	// Maven layout.
	if err := os.WriteFile(filepath.Join(tmp, "pom.xml"),
		[]byte(`<project></project>`), 0o644); err != nil {
		t.Fatal(err)
	}
	srcRoot := filepath.Join(tmp, "src", "main", "java")
	svcDir := filepath.Join(srcRoot, "com", "example", "service")
	if err := os.MkdirAll(svcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	svcFile := filepath.Join(svcDir, "UserService.java")
	if err := os.WriteFile(svcFile,
		[]byte("package com.example.service;\npublic class UserService { public String find() { return null; } }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	webDir := filepath.Join(srcRoot, "com", "example", "web")
	if err := os.MkdirAll(webDir, 0o755); err != nil {
		t.Fatal(err)
	}
	ctrlFile := filepath.Join(webDir, "UserController.java")
	ctrlSrc := `package com.example.web;

import com.example.service.UserService;
import java.util.List;

public class UserController {
}
`
	if err := os.WriteFile(ctrlFile, []byte(ctrlSrc), 0o644); err != nil {
		t.Fatal(err)
	}

	r := &javaResolver{}
	scope, err := r.ExtractScope(ctrlFile, []byte(ctrlSrc))
	if err != nil {
		t.Fatalf("ExtractScope: %v", err)
	}
	if scope.Package != "com.example.web" {
		t.Errorf("scope.Package = %q, want com.example.web", scope.Package)
	}
	// UserService should be bound to the absolute path of its .java
	// file; java.util.List should be bound to its FQN (extern).
	wantPath, _ := filepath.Abs(svcFile)
	if got := scope.Imports["UserService"]; got != wantPath {
		t.Errorf("Imports[UserService] = %q, want %q", got, wantPath)
	}
	if got := scope.Imports["List"]; got != "java.util.List" {
		t.Errorf("Imports[List] = %q, want java.util.List (extern)", got)
	}
}

// TestJavaResolver_ExtractScope_StarImport: `import com.foo.bar.*;`
// records the package directory in StarImports, doesn't bind a short
// name in Imports.
func TestJavaResolver_ExtractScope_StarImport(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "pom.xml"),
		[]byte(`<project></project>`), 0o644); err != nil {
		t.Fatal(err)
	}
	srcRoot := filepath.Join(tmp, "src", "main", "java")
	utilDir := filepath.Join(srcRoot, "com", "example", "util")
	if err := os.MkdirAll(utilDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Anything inside utilDir — the resolver just stats the directory.
	if err := os.WriteFile(filepath.Join(utilDir, "Helpers.java"),
		[]byte("package com.example.util;\npublic class Helpers {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	webDir := filepath.Join(srcRoot, "com", "example", "web")
	if err := os.MkdirAll(webDir, 0o755); err != nil {
		t.Fatal(err)
	}
	src := `package com.example.web;

import com.example.util.*;

public class App {}
`
	r := &javaResolver{}
	scope, err := r.ExtractScope(filepath.Join(webDir, "App.java"), []byte(src))
	if err != nil {
		t.Fatalf("ExtractScope: %v", err)
	}
	if len(scope.StarImports) == 0 {
		t.Fatalf("StarImports empty; want one entry for com.example.util")
	}
	wantDir, _ := filepath.Abs(utilDir)
	gotDir := scope.StarImports[0]
	if absGot, err := filepath.Abs(gotDir); err == nil {
		gotDir = absGot
	}
	if gotDir != wantDir {
		t.Errorf("StarImports[0] = %q, want %q", gotDir, wantDir)
	}
}

// TestJavaResolver_ExtractScope_StdlibImportsReturnExtern: imports of
// java.*, javax.*, jakarta.*, org.springframework.* should bind to
// the FQN (extern), not try to resolve to a file.
func TestJavaResolver_ExtractScope_StdlibImportsReturnExtern(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "pom.xml"),
		[]byte(`<project></project>`), 0o644); err != nil {
		t.Fatal(err)
	}
	srcRoot := filepath.Join(tmp, "src", "main", "java")
	webDir := filepath.Join(srcRoot, "com", "example", "web")
	if err := os.MkdirAll(webDir, 0o755); err != nil {
		t.Fatal(err)
	}
	src := `package com.example.web;

import java.util.List;
import javax.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;

public class App {}
`
	r := &javaResolver{}
	scope, err := r.ExtractScope(filepath.Join(webDir, "App.java"), []byte(src))
	if err != nil {
		t.Fatalf("ExtractScope: %v", err)
	}
	wants := map[string]string{
		"List":                 "java.util.List",
		"HttpServletRequest":   "javax.servlet.http.HttpServletRequest",
		"Service":              "org.springframework.stereotype.Service",
	}
	for k, v := range wants {
		if got := scope.Imports[k]; got != v {
			t.Errorf("Imports[%q] = %q, want %q", k, got, v)
		}
	}
}

// TestJavaResolver_ResolveCall_ImportedClass: `import com.example.service.UserService;`
// in main resolves the cross-file call `UserService.find()` to the node
// in the imported file.
func TestJavaResolver_ResolveCall_ImportedClass(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "pom.xml"),
		[]byte(`<project></project>`), 0o644); err != nil {
		t.Fatal(err)
	}
	srcRoot := filepath.Join(root, "src", "main", "java")
	svcDir := filepath.Join(srcRoot, "com", "example", "service")
	webDir := filepath.Join(srcRoot, "com", "example", "web")
	if err := os.MkdirAll(svcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(webDir, 0o755); err != nil {
		t.Fatal(err)
	}
	svcFile := filepath.Join(svcDir, "UserService.java")
	ctrlFile := filepath.Join(webDir, "UserController.java")
	svcSrc := `package com.example.service;
public class UserService {
    public static String find(String id) { return id; }
}
`
	ctrlSrc := `package com.example.web;
import com.example.service.UserService;
public class UserController {
    public String show(String id) {
        return UserService.find(id);
    }
}
`
	if err := os.WriteFile(svcFile, []byte(svcSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ctrlFile, []byte(ctrlSrc), 0o644); err != nil {
		t.Fatal(err)
	}

	svcAbs, _ := filepath.Abs(svcFile)
	ctrlAbs, _ := filepath.Abs(ctrlFile)

	cg := NewCallGraph(root, "test")
	cg.AddNode(&FuncNode{
		ID:       ctrlAbs + ":UserController.show",
		FilePath: ctrlAbs,
		Name:     "UserController.show",
		Language: rules.LangJava,
		RawCalls: []string{"UserService.find"},
	})
	cg.AddNode(&FuncNode{
		ID:       svcAbs + ":UserService.find",
		FilePath: svcAbs,
		Name:     "UserService.find",
		Language: rules.LangJava,
	})

	contents := map[string][]byte{
		svcAbs:  []byte(svcSrc),
		ctrlAbs: []byte(ctrlSrc),
	}
	stats := ResolveCrossFileEdges(cg, root, contents)
	if stats.CrossFileEdges < 1 {
		t.Errorf("CrossFileEdges = %d, want >= 1 (stats=%+v)", stats.CrossFileEdges, stats)
	}
	caller := cg.GetNode(ctrlAbs + ":UserController.show")
	wantTarget := svcAbs + ":UserService.find"
	if !containsStr(caller.Calls, wantTarget) {
		t.Errorf("caller.Calls missing %q (got %v)", wantTarget, caller.Calls)
	}
}

// TestJavaResolver_ResolveCall_SamePackageNoImport: classes in the same
// package can call each other without an explicit import. The resolver
// probes the package directory.
func TestJavaResolver_ResolveCall_SamePackageNoImport(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "pom.xml"),
		[]byte(`<project></project>`), 0o644); err != nil {
		t.Fatal(err)
	}
	srcRoot := filepath.Join(root, "src", "main", "java")
	pkgDir := filepath.Join(srcRoot, "com", "example")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	helperFile := filepath.Join(pkgDir, "Helper.java")
	mainFile := filepath.Join(pkgDir, "Main.java")
	helperSrc := `package com.example;
public class Helper {
    public static String greet(String n) { return "hi " + n; }
}
`
	mainSrc := `package com.example;
public class Main {
    public String run(String n) {
        return Helper.greet(n);
    }
}
`
	if err := os.WriteFile(helperFile, []byte(helperSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mainFile, []byte(mainSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	helperAbs, _ := filepath.Abs(helperFile)
	mainAbs, _ := filepath.Abs(mainFile)

	cg := NewCallGraph(root, "test")
	cg.AddNode(&FuncNode{
		ID:       mainAbs + ":Main.run",
		FilePath: mainAbs,
		Name:     "Main.run",
		Language: rules.LangJava,
		RawCalls: []string{"Helper.greet"},
	})
	cg.AddNode(&FuncNode{
		ID:       helperAbs + ":Helper.greet",
		FilePath: helperAbs,
		Name:     "Helper.greet",
		Language: rules.LangJava,
	})

	contents := map[string][]byte{
		helperAbs: []byte(helperSrc),
		mainAbs:   []byte(mainSrc),
	}
	ResolveCrossFileEdges(cg, root, contents)
	caller := cg.GetNode(mainAbs + ":Main.run")
	wantTarget := helperAbs + ":Helper.greet"
	if !containsStr(caller.Calls, wantTarget) {
		t.Errorf("same-package call did not resolve: caller.Calls = %v, want %q",
			caller.Calls, wantTarget)
	}
}

// TestJavaResolver_ResolveCall_StdlibReturnsExtern: an import of
// java.util.Random + a `new Random()` call should route to extern.
func TestJavaResolver_ResolveCall_StdlibReturnsExtern(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "pom.xml"),
		[]byte(`<project></project>`), 0o644); err != nil {
		t.Fatal(err)
	}
	srcRoot := filepath.Join(root, "src", "main", "java")
	webDir := filepath.Join(srcRoot, "com", "example")
	if err := os.MkdirAll(webDir, 0o755); err != nil {
		t.Fatal(err)
	}
	mainFile := filepath.Join(webDir, "Main.java")
	mainSrc := `package com.example;
import java.util.Random;
public class Main {
    public int pick() {
        return Random.nextInt();
    }
}
`
	if err := os.WriteFile(mainFile, []byte(mainSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	mainAbs, _ := filepath.Abs(mainFile)
	cg := NewCallGraph(root, "test")
	cg.AddNode(&FuncNode{
		ID:       mainAbs + ":Main.pick",
		FilePath: mainAbs,
		Name:     "Main.pick",
		Language: rules.LangJava,
		RawCalls: []string{"Random.nextInt"},
	})
	contents := map[string][]byte{mainAbs: []byte(mainSrc)}
	ResolveCrossFileEdges(cg, root, contents)
	caller := cg.GetNode(mainAbs + ":Main.pick")
	want := "java.util.Random.nextInt"
	if !containsStr(caller.ExternCalls, want) {
		t.Errorf("ExternCalls missing %q (got %v)", want, caller.ExternCalls)
	}
}

// TestJavaResolver_FindModuleRoot_SrcLayout: a file deep in
// src/main/java/com/foo/bar/X.java should resolve its module root to
// src/main/java when a pom.xml sits at the project root.
func TestJavaResolver_FindModuleRoot_SrcLayout(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "pom.xml"),
		[]byte(`<project></project>`), 0o644); err != nil {
		t.Fatal(err)
	}
	srcRoot := filepath.Join(tmp, "src", "main", "java")
	deep := filepath.Join(srcRoot, "com", "example", "deep")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(deep, "X.java")
	if err := os.WriteFile(file, []byte("package com.example.deep;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := findJavaModuleRoot(file)
	if got != srcRoot {
		t.Errorf("findJavaModuleRoot = %q, want %q", got, srcRoot)
	}
}

// TestJavaResolver_FindModuleRoot_NoSrcLayout: with a pom.xml but no
// src/main/java, the module root is the manifest directory itself.
func TestJavaResolver_FindModuleRoot_NoSrcLayout(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "pom.xml"),
		[]byte(`<project></project>`), 0o644); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(tmp, "Flat.java")
	if err := os.WriteFile(file, []byte("public class Flat {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := findJavaModuleRoot(file)
	wantAbs, _ := filepath.Abs(tmp)
	gotAbs, _ := filepath.Abs(got)
	if gotAbs != wantAbs {
		t.Errorf("findJavaModuleRoot = %q, want %q", got, tmp)
	}
}

// TestJavaResolver_ResolveJavaImportToFile_Roundtrip exercises the
// FQN → absolute-path helper.
func TestJavaResolver_ResolveJavaImportToFile_Roundtrip(t *testing.T) {
	tmp := t.TempDir()
	deep := filepath.Join(tmp, "com", "example", "deep")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(deep, "Widget.java")
	if err := os.WriteFile(file, []byte("package com.example.deep;\npublic class Widget {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := resolveJavaImportToFile("com.example.deep.Widget", tmp)
	wantAbs, _ := filepath.Abs(file)
	if got != wantAbs {
		t.Errorf("resolveJavaImportToFile = %q, want %q", got, wantAbs)
	}
	// Missing class returns empty.
	if got := resolveJavaImportToFile("com.example.deep.Missing", tmp); got != "" {
		t.Errorf("missing class should return empty, got %q", got)
	}
}

// TestJavaResolver_IsJavaExternFQN spot-checks the prefix list.
func TestJavaResolver_IsJavaExternFQN(t *testing.T) {
	cases := map[string]bool{
		"java.util.List":                       true,
		"javax.servlet.http.HttpServletRequest": true,
		"jakarta.persistence.EntityManager":    true,
		"org.springframework.stereotype.Bean":  true,
		"org.junit.Test":                       true,
		"com.example.app.UserService":          false,
		"":                                     false,
	}
	for fqn, want := range cases {
		if got := isJavaExternFQN(fqn); got != want {
			t.Errorf("isJavaExternFQN(%q) = %v, want %v", fqn, got, want)
		}
	}
}
