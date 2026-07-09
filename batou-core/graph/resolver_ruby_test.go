package graph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// TestRubyResolver_Registered confirms init() wired the Ruby resolver
// into the registry.
func TestRubyResolver_Registered(t *testing.T) {
	if GetResolver(rules.LangRuby) == nil {
		t.Fatal("Ruby resolver not registered")
	}
}

// TestRubyResolver_ProjectRoot_GemfileLayout: a Gemfile at the scan
// root anchors the module root.
func TestRubyResolver_ProjectRoot_GemfileLayout(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "Gemfile"),
		[]byte(`source 'https://rubygems.org'`), 0o644); err != nil {
		t.Fatal(err)
	}
	libDir := filepath.Join(tmp, "lib", "myapp")
	if err := os.MkdirAll(libDir, 0o755); err != nil {
		t.Fatal(err)
	}
	r := &rubyResolver{}
	manifest, mod, ok := r.ProjectRoot(libDir)
	if !ok {
		t.Fatalf("ProjectRoot did not find manifest from %q", libDir)
	}
	if mod != "" {
		t.Errorf("ProjectRoot module = %q, want empty (Ruby has no global module prefix)", mod)
	}
	if filepath.Dir(manifest) != tmp {
		t.Errorf("manifest dir = %q, want %q", filepath.Dir(manifest), tmp)
	}
}

// TestRubyResolver_ProjectRoot_NoManifest: scripts-only directory still
// returns ok=true so the resolver can anchor somewhere.
func TestRubyResolver_ProjectRoot_NoManifest(t *testing.T) {
	tmp := t.TempDir()
	r := &rubyResolver{}
	_, _, ok := r.ProjectRoot(tmp)
	if !ok {
		t.Fatal("ProjectRoot should return ok=true even without manifests")
	}
}

// TestRubyResolver_ProjectRoot_LibDirAnchor: a directory containing a
// `lib/` subdirectory but no manifest file still anchors as the module
// root (lib-only gems / unpacked gem trees).
func TestRubyResolver_ProjectRoot_LibDirAnchor(t *testing.T) {
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := &rubyResolver{}
	manifest, _, ok := r.ProjectRoot(tmp)
	if !ok {
		t.Fatal("ProjectRoot should return ok=true with lib/ present")
	}
	if filepath.Dir(manifest) != tmp {
		t.Errorf("manifest dir = %q, want %q", filepath.Dir(manifest), tmp)
	}
}

// TestRubyResolver_ExtractScope_RequireRelative verifies a
// `require_relative './foo'` binds the alias `foo` to the resolved
// absolute path of foo.rb.
func TestRubyResolver_ExtractScope_RequireRelative(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "Gemfile"), []byte(``), 0o644); err != nil {
		t.Fatal(err)
	}
	fooFile := filepath.Join(tmp, "foo.rb")
	if err := os.WriteFile(fooFile, []byte("class Foo; def m; end; end\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mainFile := filepath.Join(tmp, "main.rb")
	src := `require_relative './foo'

class Main
end
`
	if err := os.WriteFile(mainFile, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	r := &rubyResolver{}
	scope, err := r.ExtractScope(mainFile, []byte(src))
	if err != nil {
		t.Fatalf("ExtractScope: %v", err)
	}
	wantPath, _ := filepath.Abs(fooFile)
	if got := scope.Imports["foo"]; got != wantPath {
		t.Errorf("Imports[foo] = %q, want %q", got, wantPath)
	}
}

// TestRubyResolver_ExtractScope_RequireLib resolves `require 'foo'`
// to `lib/foo.rb` when the Rails-style layout is present.
func TestRubyResolver_ExtractScope_RequireLib(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "Gemfile"), []byte(``), 0o644); err != nil {
		t.Fatal(err)
	}
	libDir := filepath.Join(tmp, "lib")
	if err := os.MkdirAll(libDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fooFile := filepath.Join(libDir, "foo.rb")
	if err := os.WriteFile(fooFile, []byte("class Foo; end\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mainFile := filepath.Join(tmp, "main.rb")
	src := `require 'foo'

class Main
end
`
	if err := os.WriteFile(mainFile, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	r := &rubyResolver{}
	scope, err := r.ExtractScope(mainFile, []byte(src))
	if err != nil {
		t.Fatalf("ExtractScope: %v", err)
	}
	wantPath, _ := filepath.Abs(fooFile)
	if got := scope.Imports["foo"]; got != wantPath {
		t.Errorf("Imports[foo] = %q, want %q (lib/-resolved)", got, wantPath)
	}
}

// TestRubyResolver_ExtractScope_StdlibImportsReturnExtern: imports of
// `rails`, `sinatra`, `json`, etc. resolve to the bare specifier
// (extern), not a file path.
func TestRubyResolver_ExtractScope_StdlibImportsReturnExtern(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "Gemfile"), []byte(``), 0o644); err != nil {
		t.Fatal(err)
	}
	src := `require 'sinatra'
require 'json'
require 'rails/all'
require 'active_record'
`
	r := &rubyResolver{}
	scope, err := r.ExtractScope(filepath.Join(tmp, "app.rb"), []byte(src))
	if err != nil {
		t.Fatalf("ExtractScope: %v", err)
	}
	// Each stdlib/gem alias should map to its bare specifier (not an
	// absolute path).
	wants := map[string]string{
		"sinatra":       "sinatra",
		"json":          "json",
		"all":           "rails/all",
		"active_record": "active_record",
	}
	for k, v := range wants {
		if got := scope.Imports[k]; got != v {
			t.Errorf("Imports[%q] = %q, want %q", k, got, v)
		}
	}
}

// TestRubyResolver_ExtractScope_Autoload binds the constant from
// `autoload :Foo, 'foo'` to either the resolved path or the bare spec.
func TestRubyResolver_ExtractScope_Autoload(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "Gemfile"), []byte(``), 0o644); err != nil {
		t.Fatal(err)
	}
	libDir := filepath.Join(tmp, "lib")
	if err := os.MkdirAll(libDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fooFile := filepath.Join(libDir, "foo.rb")
	if err := os.WriteFile(fooFile, []byte("class Foo; def bar; end; end\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := `autoload :Foo, 'foo'

class Main
end
`
	r := &rubyResolver{}
	scope, err := r.ExtractScope(filepath.Join(tmp, "main.rb"), []byte(src))
	if err != nil {
		t.Fatalf("ExtractScope: %v", err)
	}
	wantPath, _ := filepath.Abs(fooFile)
	if got := scope.Imports["Foo"]; got != wantPath {
		t.Errorf("Imports[Foo] = %q, want %q (autoload-resolved)", got, wantPath)
	}
}

// TestRubyResolver_ResolveCall_ImportedClass: `require_relative './user_service'`
// in main resolves a cross-file call `UserService.find` to the node in
// the imported file via the CamelCase→snake_case fallback.
func TestRubyResolver_ResolveCall_ImportedClass(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "Gemfile"), []byte(``), 0o644); err != nil {
		t.Fatal(err)
	}
	svcFile := filepath.Join(root, "user_service.rb")
	ctrlFile := filepath.Join(root, "controller.rb")
	svcSrc := `class UserService
  def self.find(id)
    id
  end
end
`
	ctrlSrc := `require_relative './user_service'

class Controller
  def show(id)
    UserService.find(id)
  end
end
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
		ID:       ctrlAbs + ":Controller.show",
		FilePath: ctrlAbs,
		Name:     "Controller.show",
		Language: rules.LangRuby,
		RawCalls: []string{"UserService.find"},
	})
	cg.AddNode(&FuncNode{
		ID:       svcAbs + ":UserService.find",
		FilePath: svcAbs,
		Name:     "UserService.find",
		Language: rules.LangRuby,
	})

	contents := map[string][]byte{
		svcAbs:  []byte(svcSrc),
		ctrlAbs: []byte(ctrlSrc),
	}
	stats := ResolveCrossFileEdges(cg, root, contents)
	if stats.CrossFileEdges < 1 {
		t.Errorf("CrossFileEdges = %d, want >= 1 (stats=%+v)", stats.CrossFileEdges, stats)
	}
	caller := cg.GetNode(ctrlAbs + ":Controller.show")
	wantTarget := svcAbs + ":UserService.find"
	if !containsStr(caller.Calls, wantTarget) {
		t.Errorf("caller.Calls missing %q (got %v)", wantTarget, caller.Calls)
	}
}

// TestRubyResolver_ResolveCall_GemReturnsExtern: a `require 'json'` +
// `JSON.parse` call should route to extern (since `json` is a known
// stdlib prefix).
func TestRubyResolver_ResolveCall_GemReturnsExtern(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "Gemfile"), []byte(``), 0o644); err != nil {
		t.Fatal(err)
	}
	mainFile := filepath.Join(root, "main.rb")
	mainSrc := `require 'json'

class Main
  def parse(s)
    json.parse(s)
  end
end
`
	if err := os.WriteFile(mainFile, []byte(mainSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	mainAbs, _ := filepath.Abs(mainFile)
	cg := NewCallGraph(root, "test")
	cg.AddNode(&FuncNode{
		ID:       mainAbs + ":Main.parse",
		FilePath: mainAbs,
		Name:     "Main.parse",
		Language: rules.LangRuby,
		// `json.parse` — receiver matches the alias from `require 'json'`.
		RawCalls: []string{"json.parse"},
	})
	contents := map[string][]byte{mainAbs: []byte(mainSrc)}
	ResolveCrossFileEdges(cg, root, contents)
	caller := cg.GetNode(mainAbs + ":Main.parse")
	want := "json.parse"
	if !containsStr(caller.ExternCalls, want) {
		t.Errorf("ExternCalls missing %q (got %v)", want, caller.ExternCalls)
	}
}

// TestRubyResolver_FindModuleRoot_GemfileAncestor: a file deep in
// lib/myapp/handler.rb should resolve its module root to the Gemfile's
// directory.
func TestRubyResolver_FindModuleRoot_GemfileAncestor(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "Gemfile"), []byte(``), 0o644); err != nil {
		t.Fatal(err)
	}
	deep := filepath.Join(tmp, "lib", "myapp")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(deep, "handler.rb")
	if err := os.WriteFile(file, []byte("class Handler; end\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := findRubyModuleRoot(file)
	if got != tmp {
		t.Errorf("findRubyModuleRoot = %q, want %q", got, tmp)
	}
}

// TestRubyResolver_IsRubyExternSpecifier spot-checks the prefix list.
func TestRubyResolver_IsRubyExternSpecifier(t *testing.T) {
	cases := map[string]bool{
		"sinatra":              true,
		"rails/all":            true,
		"active_record":        true,
		"action_controller":    true,
		"json":                 true,
		"net/http":             true,
		"my_app/internal":      false,
		"./local_module":       false,
		"":                     false,
	}
	for spec, want := range cases {
		if got := isRubyExternSpecifier(spec); got != want {
			t.Errorf("isRubyExternSpecifier(%q) = %v, want %v", spec, got, want)
		}
	}
}

// TestRubyResolver_CamelToSnake spot-checks the CamelCase → snake_case
// helper that bridges Ruby constant names to file basenames.
func TestRubyResolver_CamelToSnake(t *testing.T) {
	cases := map[string]string{
		"User":         "user",
		"UserService":  "user_service",
		"HTMLParser":   "html_parser",
		"":             "",
		"user_service": "user_service",
	}
	for in, want := range cases {
		if got := rubyCamelToSnake(in); got != want {
			t.Errorf("rubyCamelToSnake(%q) = %q, want %q", in, got, want)
		}
	}
}
