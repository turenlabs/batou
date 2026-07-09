package graph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// TestJSResolver_Registered confirms init() wired both JS and TS
// resolvers into the registry.
func TestJSResolver_Registered(t *testing.T) {
	if GetResolver(rules.LangJavaScript) == nil {
		t.Fatal("JavaScript resolver not registered")
	}
	if GetResolver(rules.LangTypeScript) == nil {
		t.Fatal("TypeScript resolver not registered")
	}
}

// TestJSResolver_ProjectRoot_PackageJSON verifies the manifest walk
// finds package.json and reads the name field.
func TestJSResolver_ProjectRoot_PackageJSON(t *testing.T) {
	tmp := t.TempDir()
	pkgJSON := `{
  "name": "myapp",
  "version": "1.0.0"
}
`
	if err := os.WriteFile(filepath.Join(tmp, "package.json"), []byte(pkgJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(tmp, "src", "handlers")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	r := &jsResolver{lang: rules.LangJavaScript}
	manifest, mod, ok := r.ProjectRoot(sub)
	if !ok {
		t.Fatalf("ProjectRoot did not find manifest from %q", sub)
	}
	if mod != "myapp" {
		t.Errorf("ProjectRoot module = %q, want myapp", mod)
	}
	if filepath.Clean(manifest) != filepath.Join(tmp, "package.json") {
		t.Errorf("manifest = %q, want %q", manifest, filepath.Join(tmp, "package.json"))
	}
}

// TestJSResolver_ProjectRoot_NoManifest covers the script-only fallback:
// no package.json anywhere — still returns ok=true so JS files work.
func TestJSResolver_ProjectRoot_NoManifest(t *testing.T) {
	tmp := t.TempDir()
	r := &jsResolver{lang: rules.LangJavaScript}
	_, mod, ok := r.ProjectRoot(tmp)
	if !ok {
		t.Fatal("ProjectRoot should return ok=true for script-only repos")
	}
	if mod != "" {
		t.Errorf("module = %q, want empty (no manifest)", mod)
	}
}

// TestJSResolver_ResolveSpecifier_Extensions exercises the
// extension-fallback chain for an extension-less relative specifier.
func TestJSResolver_ResolveSpecifier_Extensions(t *testing.T) {
	tmp := t.TempDir()
	// Create a few candidate files so we can verify the precedence.
	jsPath := filepath.Join(tmp, "foo.js")
	tsPath := filepath.Join(tmp, "foo.ts")
	if err := os.WriteFile(jsPath, []byte("// noop\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tsPath, []byte("// noop\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// With both `foo.ts` and `foo.js` present, `./foo` resolves to `.ts`
	// (higher in the precedence list).
	got := resolveJSSpecifier(tmp, "./foo", nil)
	wantAbs, _ := filepath.Abs(tsPath)
	if got != wantAbs {
		t.Errorf("resolveJSSpecifier(./foo) = %q, want %q (.ts preferred over .js)", got, wantAbs)
	}
	// Remove the .ts file — now ./foo should fall through to ./foo.js.
	if err := os.Remove(tsPath); err != nil {
		t.Fatal(err)
	}
	got = resolveJSSpecifier(tmp, "./foo", nil)
	wantAbs, _ = filepath.Abs(jsPath)
	if got != wantAbs {
		t.Errorf("resolveJSSpecifier(./foo) after removing .ts = %q, want %q", got, wantAbs)
	}
}

// TestJSResolver_ResolveSpecifier_UpwardPath verifies that `../foo`
// resolves relative to the importing file's directory.
func TestJSResolver_ResolveSpecifier_UpwardPath(t *testing.T) {
	tmp := t.TempDir()
	subDir := filepath.Join(tmp, "sub")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(tmp, "sibling.js")
	if err := os.WriteFile(parent, []byte("// noop\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := resolveJSSpecifier(subDir, "../sibling", nil)
	wantAbs, _ := filepath.Abs(parent)
	if got != wantAbs {
		t.Errorf("resolveJSSpecifier(../sibling) = %q, want %q", got, wantAbs)
	}
}

// TestJSResolver_ResolveSpecifier_IndexFile verifies the directory →
// `index.js` fallback.
func TestJSResolver_ResolveSpecifier_IndexFile(t *testing.T) {
	tmp := t.TempDir()
	pkgDir := filepath.Join(tmp, "pkg")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	indexPath := filepath.Join(pkgDir, "index.js")
	if err := os.WriteFile(indexPath, []byte("// noop\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := resolveJSSpecifier(tmp, "./pkg", nil)
	wantAbs, _ := filepath.Abs(indexPath)
	if got != wantAbs {
		t.Errorf("resolveJSSpecifier(./pkg) = %q, want %q (index.js fallback)", got, wantAbs)
	}
}

// TestJSResolver_ResolveSpecifier_BareReturnsEmpty: bare specifiers
// (react, @scope/x, lodash) return empty — node_modules out of scope.
func TestJSResolver_ResolveSpecifier_BareReturnsEmpty(t *testing.T) {
	tmp := t.TempDir()
	for _, spec := range []string{"react", "@scope/lib", "lodash", "fs"} {
		if got := resolveJSSpecifier(tmp, spec, nil); got != "" {
			t.Errorf("resolveJSSpecifier(%q) = %q, want empty (bare specifier)", spec, got)
		}
	}
}

// TestJSResolver_ResolveSpecifier_ExplicitExtension: when the specifier
// already has an extension, we use it as-is (no fallback).
func TestJSResolver_ResolveSpecifier_ExplicitExtension(t *testing.T) {
	tmp := t.TempDir()
	mjsPath := filepath.Join(tmp, "foo.mjs")
	if err := os.WriteFile(mjsPath, []byte("// noop\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := resolveJSSpecifier(tmp, "./foo.mjs", nil)
	wantAbs, _ := filepath.Abs(mjsPath)
	if got != wantAbs {
		t.Errorf("resolveJSSpecifier(./foo.mjs) = %q, want %q (explicit ext)", got, wantAbs)
	}
}

// TestJSResolver_ExtractScope_ESMImports verifies the major ESM shapes
// produce a populated Imports map.
func TestJSResolver_ExtractScope_ESMImports(t *testing.T) {
	tmp := t.TempDir()
	// Create the imported modules so resolveJSSpecifier finds them.
	for _, name := range []string{"foo.js", "bar.js", "baz.js"} {
		p := filepath.Join(tmp, name)
		if err := os.WriteFile(p, []byte("// noop\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	src := `import X from './foo';
import {Y, Z as W} from './bar';
import * as ns from './baz';
`
	r := &jsResolver{lang: rules.LangJavaScript}
	scope, err := r.ExtractScope(filepath.Join(tmp, "main.js"), []byte(src))
	if err != nil {
		t.Fatalf("ExtractScope: %v", err)
	}
	fooAbs, _ := filepath.Abs(filepath.Join(tmp, "foo.js"))
	barAbs, _ := filepath.Abs(filepath.Join(tmp, "bar.js"))
	bazAbs, _ := filepath.Abs(filepath.Join(tmp, "baz.js"))

	wants := map[string]string{
		"X":  fooAbs, // default import
		"Y":  barAbs, // named import
		"W":  barAbs, // aliased named import (Z as W)
		"ns": bazAbs, // namespace import
	}
	for k, v := range wants {
		if got := scope.Imports[k]; got != v {
			t.Errorf("Imports[%q] = %q, want %q", k, got, v)
		}
	}
}

// TestJSResolver_ExtractScope_CommonJSRequire: `const x = require('./y')`
// shapes resolve to absolute paths.
func TestJSResolver_ExtractScope_CommonJSRequire(t *testing.T) {
	tmp := t.TempDir()
	bazPath := filepath.Join(tmp, "baz.js")
	if err := os.WriteFile(bazPath, []byte("// noop\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := `const x = require('./baz');
const y = require('./baz').sub;
const {a, b: c} = require('./baz');
`
	r := &jsResolver{lang: rules.LangJavaScript}
	scope, err := r.ExtractScope(filepath.Join(tmp, "main.js"), []byte(src))
	if err != nil {
		t.Fatalf("ExtractScope: %v", err)
	}
	bazAbs, _ := filepath.Abs(bazPath)
	for _, alias := range []string{"x", "y", "a", "c"} {
		if got := scope.Imports[alias]; got != bazAbs {
			t.Errorf("Imports[%q] = %q, want %q", alias, got, bazAbs)
		}
	}
}

// TestJSResolver_ExtractScope_DynamicImportSyntax: `import('./foo')` is
// a call expression, not a static import statement — we don't expose it
// in scope.Imports today (the alias only exists at the await site). The
// shape parses without crashing.
func TestJSResolver_ExtractScope_DynamicImportSyntax(t *testing.T) {
	tmp := t.TempDir()
	dynPath := filepath.Join(tmp, "dynamic.js")
	if err := os.WriteFile(dynPath, []byte("// noop\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := `async function load() {
  const mod = await import('./dynamic');
  return mod.thing;
}
`
	r := &jsResolver{lang: rules.LangJavaScript}
	scope, err := r.ExtractScope(filepath.Join(tmp, "main.js"), []byte(src))
	if err != nil {
		t.Fatalf("ExtractScope: %v", err)
	}
	// We don't track dynamic-import aliases; the scope is empty for them.
	// What we DO assert: no crash and the file's Package still set.
	if scope.Package == "" {
		t.Error("scope.Package not set")
	}
}

// TestJSResolver_ResolveCall_ImportedFunc: headline test — main.js
// imports `handler` from './sources.js' and calls it. The cross-file
// resolution wires the edge.
func TestJSResolver_ResolveCall_ImportedFunc(t *testing.T) {
	root := t.TempDir()
	// Provide a package.json so ProjectRoot anchors at root.
	if err := os.WriteFile(filepath.Join(root, "package.json"),
		[]byte(`{"name":"proj"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	sourcesPath := filepath.Join(root, "sources.js")
	mainPath := filepath.Join(root, "main.js")

	sourcesAbs, _ := filepath.Abs(sourcesPath)
	mainAbs, _ := filepath.Abs(mainPath)

	cg := NewCallGraph(root, "test")
	cg.AddNode(&FuncNode{
		ID:       mainAbs + ":caller",
		FilePath: mainAbs,
		Name:     "caller",
		Language: rules.LangJavaScript,
		RawCalls: []string{"handler"},
	})
	cg.AddNode(&FuncNode{
		ID:       sourcesAbs + ":handler",
		FilePath: sourcesAbs,
		Name:     "handler",
		Language: rules.LangJavaScript,
	})

	// Write the source files to disk so resolveJSSpecifier can find them.
	if err := os.WriteFile(sourcesPath, []byte("function handler(req) { return req.body; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mainPath, []byte("import {handler} from './sources';\nfunction caller() { return handler(); }\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	contents := map[string][]byte{
		sourcesAbs: []byte("function handler(req) { return req.body; }\n"),
		mainAbs:    []byte("import {handler} from './sources';\nfunction caller() { return handler(); }\n"),
	}
	stats := ResolveCrossFileEdges(cg, root, contents)
	if stats.CrossFileEdges < 1 {
		t.Errorf("CrossFileEdges = %d, want >= 1 (stats=%+v)", stats.CrossFileEdges, stats)
	}
	caller := cg.GetNode(mainAbs + ":caller")
	wantTarget := sourcesAbs + ":handler"
	if !containsStr(caller.Calls, wantTarget) {
		t.Errorf("caller.Calls missing %q (got %v)", wantTarget, caller.Calls)
	}
}

// TestJSResolver_ResolveCall_NamespaceImport: `import * as svc from './x';
// svc.handler()` resolves through the namespace alias.
func TestJSResolver_ResolveCall_NamespaceImport(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"),
		[]byte(`{"name":"proj"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	sourcesPath := filepath.Join(root, "sources.js")
	mainPath := filepath.Join(root, "main.js")
	if err := os.WriteFile(sourcesPath, []byte("export function handler(req) { return req.body; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mainPath, []byte("import * as svc from './sources';\nfunction caller() { return svc.handler(); }\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	sourcesAbs, _ := filepath.Abs(sourcesPath)
	mainAbs, _ := filepath.Abs(mainPath)

	cg := NewCallGraph(root, "test")
	cg.AddNode(&FuncNode{
		ID:       mainAbs + ":caller",
		FilePath: mainAbs,
		Name:     "caller",
		Language: rules.LangJavaScript,
		RawCalls: []string{"svc.handler"},
	})
	cg.AddNode(&FuncNode{
		ID:       sourcesAbs + ":handler",
		FilePath: sourcesAbs,
		Name:     "handler",
		Language: rules.LangJavaScript,
	})
	contents := map[string][]byte{
		sourcesAbs: []byte("export function handler(req) { return req.body; }\n"),
		mainAbs:    []byte("import * as svc from './sources';\nfunction caller() { return svc.handler(); }\n"),
	}
	ResolveCrossFileEdges(cg, root, contents)
	caller := cg.GetNode(mainAbs + ":caller")
	wantTarget := sourcesAbs + ":handler"
	if !containsStr(caller.Calls, wantTarget) {
		t.Errorf("namespace import did not resolve: caller.Calls = %v, want %q", caller.Calls, wantTarget)
	}
}

// TestJSResolver_ResolveCall_RequireCJS: CommonJS `const {handler} =
// require('./sources')` and `handler()` resolves correctly.
func TestJSResolver_ResolveCall_RequireCJS(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"),
		[]byte(`{"name":"proj"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	sourcesPath := filepath.Join(root, "sources.js")
	mainPath := filepath.Join(root, "main.js")
	if err := os.WriteFile(sourcesPath, []byte("module.exports.handler = function (req) { return req.body; };\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mainPath, []byte("const {handler} = require('./sources');\nfunction caller() { return handler(); }\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	sourcesAbs, _ := filepath.Abs(sourcesPath)
	mainAbs, _ := filepath.Abs(mainPath)

	cg := NewCallGraph(root, "test")
	cg.AddNode(&FuncNode{
		ID:       mainAbs + ":caller",
		FilePath: mainAbs,
		Name:     "caller",
		Language: rules.LangJavaScript,
		RawCalls: []string{"handler"},
	})
	cg.AddNode(&FuncNode{
		ID:       sourcesAbs + ":handler",
		FilePath: sourcesAbs,
		Name:     "handler",
		Language: rules.LangJavaScript,
	})
	contents := map[string][]byte{
		sourcesAbs: []byte("module.exports.handler = function (req) { return req.body; };\n"),
		mainAbs:    []byte("const {handler} = require('./sources');\nfunction caller() { return handler(); }\n"),
	}
	ResolveCrossFileEdges(cg, root, contents)
	caller := cg.GetNode(mainAbs + ":caller")
	wantTarget := sourcesAbs + ":handler"
	if !containsStr(caller.Calls, wantTarget) {
		t.Errorf("CommonJS require did not resolve: caller.Calls = %v, want %q", caller.Calls, wantTarget)
	}
}

// TestJSResolver_BuilderRawCalls: the JS builder emits a node for a
// top-level function and populates RawCalls so the resolver has
// something to walk.
func TestJSResolver_BuilderRawCalls(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "caller.js")
	src := `import {get_user} from './sources';

function caller() {
  const x = get_user();
  return x;
}
`
	UpdateFile(cg, filePath, src, rules.LangJavaScript)
	caller := cg.GetNode(filePath + ":caller")
	if caller == nil {
		ids := make([]string, 0)
		for _, x := range cg.NodesInFile(filePath) {
			ids = append(ids, x.ID)
		}
		t.Fatalf("caller node not built; have %v", ids)
	}
	if !containsStr(caller.RawCalls, "get_user") {
		t.Errorf("RawCalls missing 'get_user' (got %v)", caller.RawCalls)
	}
}

// TestJSResolver_BuilderClassMethodNode: the JS builder emits methods
// as "Cls.method".
func TestJSResolver_BuilderClassMethodNode(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "ctrl.js")
	src := `class UserController {
  getUser(req) {
    return req.user;
  }
}
`
	UpdateFile(cg, filePath, src, rules.LangJavaScript)
	if n := cg.GetNode(filePath + ":UserController.getUser"); n == nil {
		ids := make([]string, 0)
		for _, x := range cg.NodesInFile(filePath) {
			ids = append(ids, x.ID)
		}
		t.Errorf("UserController.getUser node not emitted; have %v", ids)
	}
}

// TestJSResolver_BuilderCommonJSExportNode verifies module.exports.X is
// keyed under X.
func TestJSResolver_BuilderCommonJSExportNode(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "cj.js")
	src := `module.exports.handler = function (req) { return req.body; };
exports.helper = function (x) { return x; };
`
	UpdateFile(cg, filePath, src, rules.LangJavaScript)
	for _, want := range []string{"handler", "helper"} {
		if n := cg.GetNode(filePath + ":" + want); n == nil {
			ids := make([]string, 0)
			for _, x := range cg.NodesInFile(filePath) {
				ids = append(ids, x.ID)
			}
			t.Errorf("CommonJS export %q not emitted as node; have %v", want, ids)
		}
	}
}

// TestJSResolver_TypeScriptFileBuilder verifies that .ts files dispatch
// to the tree-sitter-based builder via LangTypeScript.
func TestJSResolver_TypeScriptFileBuilder(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "h.ts")
	src := `export function handler(req: Request): Promise<void> {
  return req.body;
}
`
	UpdateFile(cg, filePath, src, rules.LangTypeScript)
	if n := cg.GetNode(filePath + ":handler"); n == nil {
		ids := make([]string, 0)
		for _, x := range cg.NodesInFile(filePath) {
			ids = append(ids, x.ID)
		}
		t.Errorf("TS handler node not emitted; have %v", ids)
	}
}
