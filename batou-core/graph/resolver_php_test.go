package graph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// TestPHPResolver_Registered confirms init() wired the PHP resolver
// into the registry.
func TestPHPResolver_Registered(t *testing.T) {
	if GetResolver(rules.LangPHP) == nil {
		t.Fatal("PHP resolver not registered")
	}
}

// TestPHPResolver_ProjectRoot_ComposerManifest: composer.json anchors
// the module root at its own directory.
func TestPHPResolver_ProjectRoot_ComposerManifest(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "composer.json"),
		[]byte(`{"name":"acme/app"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &phpResolver{}
	manifest, _, ok := r.ProjectRoot(tmp)
	if !ok {
		t.Fatal("ProjectRoot should return ok=true")
	}
	if filepath.Dir(manifest) != tmp {
		gotAbs, _ := filepath.Abs(filepath.Dir(manifest))
		wantAbs, _ := filepath.Abs(tmp)
		if gotAbs != wantAbs {
			t.Errorf("filepath.Dir(manifest) = %q, want %q", filepath.Dir(manifest), tmp)
		}
	}
}

// TestPHPResolver_ProjectRoot_NoManifest: scripts-only repo still
// returns ok=true so the resolver can anchor somewhere.
func TestPHPResolver_ProjectRoot_NoManifest(t *testing.T) {
	tmp := t.TempDir()
	r := &phpResolver{}
	_, _, ok := r.ProjectRoot(tmp)
	if !ok {
		t.Fatal("ProjectRoot should return ok=true even without composer.json")
	}
}

// TestPHPResolver_ExtractScope_LaravelAppLayout: with `App\` mapped to
// `app/` (Laravel convention), `use App\Service\UserService` resolves to
// app/Service/UserService.php.
func TestPHPResolver_ExtractScope_LaravelAppLayout(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "composer.json"),
		[]byte(`{"autoload":{"psr-4":{"App\\":"app/"}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	svcDir := filepath.Join(tmp, "app", "Service")
	if err := os.MkdirAll(svcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	svcFile := filepath.Join(svcDir, "UserService.php")
	if err := os.WriteFile(svcFile,
		[]byte("<?php\nnamespace App\\Service;\nclass UserService { public function find() {} }\n"),
		0o644); err != nil {
		t.Fatal(err)
	}
	ctrlDir := filepath.Join(tmp, "app", "Controllers")
	if err := os.MkdirAll(ctrlDir, 0o755); err != nil {
		t.Fatal(err)
	}
	ctrlFile := filepath.Join(ctrlDir, "UserController.php")
	ctrlSrc := `<?php
namespace App\Controllers;

use App\Service\UserService;

class UserController {
}
`
	if err := os.WriteFile(ctrlFile, []byte(ctrlSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &phpResolver{}
	scope, err := r.ExtractScope(ctrlFile, []byte(ctrlSrc))
	if err != nil {
		t.Fatalf("ExtractScope: %v", err)
	}
	if scope.Package != `App\Controllers` {
		t.Errorf("scope.Package = %q, want App\\Controllers", scope.Package)
	}
	wantPath, _ := filepath.Abs(svcFile)
	if got := scope.Imports["UserService"]; got != wantPath {
		t.Errorf("Imports[UserService] = %q, want %q", got, wantPath)
	}
}

// TestPHPResolver_ExtractScope_SymfonySrcLayout: with `App\` mapped to
// `src/`, `use App\Service\UserService` resolves to src/Service/UserService.php.
func TestPHPResolver_ExtractScope_SymfonySrcLayout(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "composer.json"),
		[]byte(`{"autoload":{"psr-4":{"App\\":"src/"}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	svcDir := filepath.Join(tmp, "src", "Service")
	if err := os.MkdirAll(svcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	svcFile := filepath.Join(svcDir, "UserService.php")
	if err := os.WriteFile(svcFile,
		[]byte("<?php\nnamespace App\\Service;\nclass UserService {}\n"),
		0o644); err != nil {
		t.Fatal(err)
	}
	ctrlSrc := `<?php
namespace App\Controllers;
use App\Service\UserService;
class C {}
`
	ctrlDir := filepath.Join(tmp, "src", "Controllers")
	if err := os.MkdirAll(ctrlDir, 0o755); err != nil {
		t.Fatal(err)
	}
	ctrlFile := filepath.Join(ctrlDir, "C.php")
	if err := os.WriteFile(ctrlFile, []byte(ctrlSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &phpResolver{}
	scope, err := r.ExtractScope(ctrlFile, []byte(ctrlSrc))
	if err != nil {
		t.Fatalf("ExtractScope: %v", err)
	}
	wantPath, _ := filepath.Abs(svcFile)
	if got := scope.Imports["UserService"]; got != wantPath {
		t.Errorf("Imports[UserService] = %q, want %q", got, wantPath)
	}
}

// TestPHPResolver_ExtractScope_DefaultMappings_AppLayout: with no
// composer.json, the default `App\` → `app/` fallback (Laravel
// convention) should still resolve the import.
func TestPHPResolver_ExtractScope_DefaultMappings_AppLayout(t *testing.T) {
	tmp := t.TempDir()
	// Marker file so findPHPModuleRoot picks tmp as the module root.
	// composer.lock counts too.
	if err := os.WriteFile(filepath.Join(tmp, "composer.lock"),
		[]byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	svcDir := filepath.Join(tmp, "app", "Service")
	if err := os.MkdirAll(svcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	svcFile := filepath.Join(svcDir, "UserService.php")
	if err := os.WriteFile(svcFile,
		[]byte("<?php\nnamespace App\\Service;\nclass UserService {}\n"),
		0o644); err != nil {
		t.Fatal(err)
	}
	ctrlDir := filepath.Join(tmp, "app", "Controllers")
	if err := os.MkdirAll(ctrlDir, 0o755); err != nil {
		t.Fatal(err)
	}
	ctrlFile := filepath.Join(ctrlDir, "UserController.php")
	ctrlSrc := `<?php
namespace App\Controllers;
use App\Service\UserService;
class UserController {}
`
	if err := os.WriteFile(ctrlFile, []byte(ctrlSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &phpResolver{}
	scope, err := r.ExtractScope(ctrlFile, []byte(ctrlSrc))
	if err != nil {
		t.Fatalf("ExtractScope: %v", err)
	}
	wantPath, _ := filepath.Abs(svcFile)
	if got := scope.Imports["UserService"]; got != wantPath {
		t.Errorf("Imports[UserService] = %q, want %q", got, wantPath)
	}
}

// TestPHPResolver_ExtractScope_GroupedUse: `use App\Util\{Helper, Logger
// as L};` binds Helper and L to their respective FQNs.
func TestPHPResolver_ExtractScope_GroupedUse(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "composer.json"),
		[]byte(`{"autoload":{"psr-4":{"App\\":"app/"}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	utilDir := filepath.Join(tmp, "app", "Util")
	if err := os.MkdirAll(utilDir, 0o755); err != nil {
		t.Fatal(err)
	}
	helperFile := filepath.Join(utilDir, "Helper.php")
	if err := os.WriteFile(helperFile,
		[]byte("<?php\nnamespace App\\Util;\nclass Helper {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	loggerFile := filepath.Join(utilDir, "Logger.php")
	if err := os.WriteFile(loggerFile,
		[]byte("<?php\nnamespace App\\Util;\nclass Logger {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := `<?php
namespace App;
use App\Util\{Helper, Logger as L};
class C {}
`
	ctrlFile := filepath.Join(tmp, "app", "C.php")
	if err := os.WriteFile(ctrlFile, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &phpResolver{}
	scope, err := r.ExtractScope(ctrlFile, []byte(src))
	if err != nil {
		t.Fatalf("ExtractScope: %v", err)
	}
	wantHelper, _ := filepath.Abs(helperFile)
	wantLogger, _ := filepath.Abs(loggerFile)
	if got := scope.Imports["Helper"]; got != wantHelper {
		t.Errorf("Imports[Helper] = %q, want %q", got, wantHelper)
	}
	// Aliased entry: bound to "L", not "Logger".
	if got := scope.Imports["L"]; got != wantLogger {
		t.Errorf("Imports[L] = %q, want %q", got, wantLogger)
	}
	if _, ok := scope.Imports["Logger"]; ok {
		t.Errorf("Imports should NOT contain Logger when aliased as L")
	}
}

// TestPHPResolver_ExtractScope_RequireDir: `require_once __DIR__ .
// '/../foo.php'` resolves relative to the importing file's directory,
// landing in StarImports.
func TestPHPResolver_ExtractScope_RequireDir(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "composer.json"),
		[]byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// Layout:
	//   tmp/foo.php           — target of the require_once
	//   tmp/sub/main.php      — has require_once __DIR__ . '/../foo.php'
	if err := os.WriteFile(filepath.Join(tmp, "foo.php"),
		[]byte("<?php\nfunction helper() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	subDir := filepath.Join(tmp, "sub")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatal(err)
	}
	mainFile := filepath.Join(subDir, "main.php")
	mainSrc := `<?php
require_once __DIR__ . '/../foo.php';

function go() {
    helper();
}
`
	if err := os.WriteFile(mainFile, []byte(mainSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &phpResolver{}
	scope, err := r.ExtractScope(mainFile, []byte(mainSrc))
	if err != nil {
		t.Fatalf("ExtractScope: %v", err)
	}
	wantTarget, _ := filepath.Abs(filepath.Join(tmp, "foo.php"))
	if len(scope.StarImports) == 0 {
		t.Fatalf("StarImports empty; want one entry for ../foo.php")
	}
	// Compare via abs path so symlinked tmpdirs match.
	got := scope.StarImports[0]
	gotAbs, _ := filepath.Abs(got)
	if gotAbs != wantTarget {
		t.Errorf("StarImports[0] = %q, want %q", got, wantTarget)
	}
}

// TestPHPResolver_ResolveCall_ImportedClass: with App\Service\UserService
// imported, `UserService::find(...)` from the controller resolves to the
// method node in the imported file.
func TestPHPResolver_ResolveCall_ImportedClass(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "composer.json"),
		[]byte(`{"autoload":{"psr-4":{"App\\":"app/"}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	svcDir := filepath.Join(root, "app", "Service")
	if err := os.MkdirAll(svcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	ctrlDir := filepath.Join(root, "app", "Controllers")
	if err := os.MkdirAll(ctrlDir, 0o755); err != nil {
		t.Fatal(err)
	}
	svcFile := filepath.Join(svcDir, "UserService.php")
	ctrlFile := filepath.Join(ctrlDir, "UserController.php")
	svcSrc := `<?php
namespace App\Service;
class UserService {
    public static function find($id) { return $id; }
}
`
	ctrlSrc := `<?php
namespace App\Controllers;
use App\Service\UserService;
class UserController {
    public function show($id) {
        return UserService::find($id);
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
		ID:       ctrlAbs + `:App\Controllers\UserController::show`,
		FilePath: ctrlAbs,
		Name:     `App\Controllers\UserController::show`,
		Language: rules.LangPHP,
		RawCalls: []string{"UserService::find"},
	})
	cg.AddNode(&FuncNode{
		ID:       svcAbs + `:App\Service\UserService::find`,
		FilePath: svcAbs,
		Name:     `App\Service\UserService::find`,
		Language: rules.LangPHP,
	})

	contents := map[string][]byte{
		svcAbs:  []byte(svcSrc),
		ctrlAbs: []byte(ctrlSrc),
	}
	stats := ResolveCrossFileEdges(cg, root, contents)
	if stats.CrossFileEdges < 1 {
		t.Errorf("CrossFileEdges = %d, want >= 1 (stats=%+v)", stats.CrossFileEdges, stats)
	}
	caller := cg.GetNode(ctrlAbs + `:App\Controllers\UserController::show`)
	wantTarget := svcAbs + `:App\Service\UserService::find`
	if !containsStr(caller.Calls, wantTarget) {
		t.Errorf("caller.Calls missing %q (got %v)", wantTarget, caller.Calls)
	}
}

// TestPHPResolver_ResolveFQNToFile_Roundtrip exercises the
// FQN-to-absolute-path helper end-to-end with a concrete file on disk.
func TestPHPResolver_ResolveFQNToFile_Roundtrip(t *testing.T) {
	tmp := t.TempDir()
	deep := filepath.Join(tmp, "app", "Foo", "Bar")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(deep, "Baz.php")
	if err := os.WriteFile(file,
		[]byte("<?php\nnamespace App\\Foo\\Bar;\nclass Baz {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mappings := []phpPSR4Entry{{Prefix: `App\`, Directory: "app"}}
	got := phpResolveFQNToFile(`App\Foo\Bar\Baz`, tmp, mappings)
	wantAbs, _ := filepath.Abs(file)
	if got != wantAbs {
		t.Errorf("phpResolveFQNToFile = %q, want %q", got, wantAbs)
	}
	if got := phpResolveFQNToFile(`App\Missing`, tmp, mappings); got != "" {
		t.Errorf("missing class should return empty, got %q", got)
	}
}

// TestPHPResolver_PHPIsBuiltinClass spot-checks the builtin list.
func TestPHPResolver_PHPIsBuiltinClass(t *testing.T) {
	cases := map[string]bool{
		"PDO":              true,
		"Exception":        true,
		"DOMDocument":      true,
		"DateTime":         true,
		"App\\Foo":         false, // namespaced names aren't builtins.
		"MyClass":          false,
		"":                 false,
	}
	for fqn, want := range cases {
		if got := phpIsBuiltinClass(fqn); got != want {
			t.Errorf("phpIsBuiltinClass(%q) = %v, want %v", fqn, got, want)
		}
	}
}

// TestPHPResolver_ReadPSR4Mappings_ParsesComposer verifies the
// composer.json parser handles both single-string and array-of-strings
// PSR-4 values and merges autoload-dev.
func TestPHPResolver_ReadPSR4Mappings_ParsesComposer(t *testing.T) {
	tmp := t.TempDir()
	src := `{
  "autoload": {
    "psr-4": {
      "App\\": "src/",
      "Acme\\Lib\\": ["lib/", "extras/"]
    }
  },
  "autoload-dev": {
    "psr-4": {
      "App\\Tests\\": "tests/"
    }
  }
}`
	if err := os.WriteFile(filepath.Join(tmp, "composer.json"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	got := phpReadPSR4Mappings(tmp, true)
	if len(got) < 4 {
		t.Fatalf("got %d mappings, want >= 4 (got=%+v)", len(got), got)
	}
	// Mappings are sorted longest-prefix-first. Verify App\Tests\ comes
	// before App\.
	for i := 0; i < len(got)-1; i++ {
		if len(got[i].Prefix) < len(got[i+1].Prefix) {
			t.Errorf("mappings not sorted longest-prefix-first: %+v", got)
			break
		}
	}
	// The Acme\Lib\ prefix should appear with both lib and extras entries.
	libCount := 0
	for _, e := range got {
		if e.Prefix == `Acme\Lib\` {
			libCount++
		}
	}
	if libCount != 2 {
		t.Errorf("Acme\\Lib\\ should have 2 directory entries, got %d", libCount)
	}
}

// TestPHPResolver_NormPSR4Prefix verifies prefix normalisation.
func TestPHPResolver_NormPSR4Prefix(t *testing.T) {
	cases := map[string]string{
		`App\`:      `App\`,
		`App\Foo\`:  `App\Foo\`,
		`App`:       `App\`, // trailing backslash added.
		``:          ``,
	}
	for in, want := range cases {
		if got := phpNormPSR4Prefix(in); got != want {
			t.Errorf("phpNormPSR4Prefix(%q) = %q, want %q", in, got, want)
		}
	}
}
