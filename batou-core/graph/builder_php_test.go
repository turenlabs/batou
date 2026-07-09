package graph

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// TestPHPBuilder_TopLevelFunction_NamespaceQualified: a function in
// `namespace App;` becomes "App\foo" in the call graph.
func TestPHPBuilder_TopLevelFunction_NamespaceQualified(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "helpers.php")
	src := `<?php
namespace App;

function sanitize($s) {
    return trim($s);
}

function wrap($s) {
    return sanitize($s);
}
`
	UpdateFile(cg, filePath, src, rules.LangPHP)
	if n := cg.GetNode(filePath + `:App\sanitize`); n == nil {
		ids := make([]string, 0)
		for _, x := range cg.NodesInFile(filePath) {
			ids = append(ids, x.ID)
		}
		t.Fatalf(`App\sanitize node not emitted; have %v`, ids)
	}
	wrap := cg.GetNode(filePath + `:App\wrap`)
	if wrap == nil {
		t.Fatal(`App\wrap node not emitted`)
	}
	if !containsStr(wrap.RawCalls, "sanitize") {
		t.Errorf(`wrap.RawCalls missing 'sanitize' (got %v)`, wrap.RawCalls)
	}
}

// TestPHPBuilder_InstanceMethod_QualifiedRawCall: `$req->getParam(...)`
// records "$req.getParam" in RawCalls (the form the resolver consumes
// for cross-file lookups on instance receivers).
func TestPHPBuilder_InstanceMethod_QualifiedRawCall(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "Servlet.php")
	src := `<?php
namespace App;
class Servlet {
    public function doGet($req) {
        $x = $req->getParam("id");
    }
}
`
	UpdateFile(cg, filePath, src, rules.LangPHP)
	n := cg.GetNode(filePath + `:App\Servlet::doGet`)
	if n == nil {
		t.Fatal(`App\Servlet::doGet node not emitted`)
	}
	if !containsStr(n.RawCalls, "$req.getParam") {
		t.Errorf("RawCalls missing '$req.getParam' (got %v)", n.RawCalls)
	}
}

// TestPHPBuilder_ScopedCall_RawCall: `Foo::bar()` records "Foo::bar" in
// RawCalls.
func TestPHPBuilder_ScopedCall_RawCall(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "Caller.php")
	src := `<?php
namespace App;
class Caller {
    public function run() {
        return Helper::find();
    }
}
`
	UpdateFile(cg, filePath, src, rules.LangPHP)
	n := cg.GetNode(filePath + `:App\Caller::run`)
	if n == nil {
		t.Fatal(`App\Caller::run node not emitted`)
	}
	if !containsStr(n.RawCalls, "Helper::find") {
		t.Errorf("RawCalls missing 'Helper::find' (got %v)", n.RawCalls)
	}
}

// TestPHPBuilder_ObjectCreation_RecordsCtor: `new Foo(...)` records
// "Foo.__construct" so the resolver can pin it to the constructor node.
func TestPHPBuilder_ObjectCreation_RecordsCtor(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "Factory.php")
	src := `<?php
namespace App;
class Factory {
    public function make($n) {
        return new User($n);
    }
}
`
	UpdateFile(cg, filePath, src, rules.LangPHP)
	n := cg.GetNode(filePath + `:App\Factory::make`)
	if n == nil {
		t.Fatal(`App\Factory::make node not emitted`)
	}
	if !containsStr(n.RawCalls, "User.__construct") {
		t.Errorf("RawCalls missing 'User.__construct' (got %v)", n.RawCalls)
	}
}

// TestPHPBuilder_ThisCallStripsReceiver: `$this->doThing()` records the
// bare "doThing" name so same-class suffix matching can find it.
func TestPHPBuilder_ThisCallStripsReceiver(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "C.php")
	src := `<?php
namespace App;
class C {
    public function caller() {
        $this->callee();
    }
    public function callee() {
        return 1;
    }
}
`
	UpdateFile(cg, filePath, src, rules.LangPHP)
	caller := cg.GetNode(filePath + `:App\C::caller`)
	if caller == nil {
		t.Fatal(`App\C::caller not emitted`)
	}
	if !containsStr(caller.RawCalls, "callee") {
		t.Errorf("RawCalls missing 'callee' for $this->callee() (got %v)", caller.RawCalls)
	}
	// Same-file edge should connect caller → callee through the suffix
	// match in buildPHPNodes.
	calleeID := filePath + `:App\C::callee`
	if !containsStr(caller.Calls, calleeID) {
		t.Errorf("caller.Calls missing %q (got %v)", calleeID, caller.Calls)
	}
}

// TestPHPBuilder_NoNamespace_BareNames: a file without
// `namespace ...;` emits bare-name FuncNodes.
func TestPHPBuilder_NoNamespace_BareNames(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "global.php")
	src := `<?php
function greet($name) {
    return "hi " . $name;
}
`
	UpdateFile(cg, filePath, src, rules.LangPHP)
	if n := cg.GetNode(filePath + ":greet"); n == nil {
		ids := make([]string, 0)
		for _, x := range cg.NodesInFile(filePath) {
			ids = append(ids, x.ID)
		}
		t.Fatalf("greet node not emitted; have %v", ids)
	}
}

// TestPHPBuilder_InterfaceAbstract_SkipBodylessMethods: methods in an
// interface or abstract methods of an abstract class should NOT be
// emitted; concrete methods should be.
func TestPHPBuilder_InterfaceAbstract_SkipBodylessMethods(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "Mixed.php")
	src := `<?php
namespace App;
interface I { public function ifaceMethod($x); }
abstract class A {
    abstract public function abs();
    public function concrete() { return 1; }
}
`
	UpdateFile(cg, filePath, src, rules.LangPHP)
	concrete := cg.GetNode(filePath + `:App\A::concrete`)
	if concrete == nil {
		t.Error(`App\A::concrete should be emitted`)
	}
	if n := cg.GetNode(filePath + `:App\I::ifaceMethod`); n != nil {
		t.Error(`interface App\I::ifaceMethod should NOT be emitted`)
	}
	if n := cg.GetNode(filePath + `:App\A::abs`); n != nil {
		t.Error(`abstract App\A::abs should NOT be emitted`)
	}
}

// TestPHPBuilder_Idempotent: calling buildPHPNodes directly twice on the
// same content reuses the existing nodes (content-hash short-circuit)
// and doesn't double the RawCalls. We invoke buildPHPNodes directly
// instead of UpdateFile because UpdateFile's outer dispatcher falls back
// to the regex builder when buildPHPNodes returns an empty updatedIDs
// slice (unchanged content) — that fallback path is a known quirk shared
// with the Java/JS builders and isn't what this test exercises.
func TestPHPBuilder_Idempotent(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "I.php")
	src := `<?php
namespace App;
class C {
    public function m() {
        helper();
    }
}
`
	buildPHPNodes(cg, filePath, src, nil)
	first := cg.GetNode(filePath + `:App\C::m`)
	if first == nil {
		t.Fatal("App\\C::m node not emitted")
	}
	rawCallsLen := len(first.RawCalls)
	buildPHPNodes(cg, filePath, src, nil)
	second := cg.GetNode(filePath + `:App\C::m`)
	if second == nil {
		t.Fatal("App\\C::m node missing after second buildPHPNodes")
	}
	if len(second.RawCalls) != rawCallsLen {
		t.Errorf("RawCalls doubled across buildPHPNodes calls: got %d, want %d (%v)",
			len(second.RawCalls), rawCallsLen, second.RawCalls)
	}
}

// TestPHPBuilder_NewQualifiedClass: `new \App\Foo()` records the short
// "Foo.__construct" so the resolver's import-aware lookup finds it.
func TestPHPBuilder_NewQualifiedClass(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "F.php")
	src := `<?php
namespace App;
class F {
    public function make() {
        return new \App\Other\Bar();
    }
}
`
	UpdateFile(cg, filePath, src, rules.LangPHP)
	n := cg.GetNode(filePath + `:App\F::make`)
	if n == nil {
		t.Fatal("App\\F::make not emitted")
	}
	found := false
	for _, c := range n.RawCalls {
		if c == "Bar.__construct" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("RawCalls missing 'Bar.__construct' for qualified new (got %v)", n.RawCalls)
	}
}

// TestPHPBuilder_ParseFailureFallsThrough confirms the fallback chain to
// buildGenericNodes when tree-sitter fails. We exercise this with empty
// content which buildPHPNodes will not parse to anything meaningful.
func TestPHPBuilder_ParseFailureFallsThrough(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "empty.php")
	// An empty content string parses to a tree with zero named children;
	// buildPHPNodes returns an empty slice (which is NOT nil), so we land
	// in the PHP path. The behaviour we want to confirm here is "doesn't
	// panic" — the integration-level guarantee.
	UpdateFile(cg, filePath, "", rules.LangPHP)
	if cnt := len(cg.NodesInFile(filePath)); cnt != 0 {
		t.Errorf("empty file should have 0 nodes, got %d", cnt)
	}
}

// TestPHPBuilder_RawCallsContainExpectedShape sanity-checks that the
// builder doesn't accidentally include keywords or noise in RawCalls.
func TestPHPBuilder_RawCallsContainExpectedShape(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "B.php")
	src := `<?php
namespace App;
function caller() {
    if (true) {
        helper();
    }
    return Cls::scoped();
}
`
	UpdateFile(cg, filePath, src, rules.LangPHP)
	n := cg.GetNode(filePath + `:App\caller`)
	if n == nil {
		t.Fatal(`App\caller not emitted`)
	}
	want := []string{"helper", "Cls::scoped"}
	for _, w := range want {
		if !containsStr(n.RawCalls, w) {
			t.Errorf("RawCalls missing %q (got %v)", w, n.RawCalls)
		}
	}
	// `if` / `true` should NOT appear in RawCalls.
	if strings.Join(n.RawCalls, ",") == "" {
		t.Errorf("expected at least helper + Cls::scoped, got empty")
	}
	for _, c := range n.RawCalls {
		if c == "if" || c == "true" {
			t.Errorf("RawCalls leaked keyword %q", c)
		}
	}
}
