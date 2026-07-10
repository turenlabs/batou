package graph

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// TestPHPExtractor_Registered confirms init() wired the PHP extractor
// into the registry.
func TestPHPExtractor_Registered(t *testing.T) {
	if !IsExtractorSupported(rules.LangPHP) {
		t.Fatal("PHP extractor not registered")
	}
}

// TestPHPExtractor_TopLevelFunction: `function handler($req) { ... }` in
// `namespace App\Controllers;` becomes "App\Controllers\handler".
func TestPHPExtractor_TopLevelFunction(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "top_level_function_with_namespace",
			FilePath: "/app/src/Handler.php",
			Content: `<?php
namespace App\Controllers;

function handler($req) {
    return $req->get('id');
}
`,
			Func: `App\Controllers\handler`,
			WantParams: []ParamTaint{
				{Index: 0, Name: "$req"},
			},
		},
	}
	RunHarness(t, rules.LangPHP, cases)
}

// TestPHPExtractor_ClassMethod_Instance: instance method gets a
// namespace-qualified "App\Foo\Cls::method" name.
func TestPHPExtractor_ClassMethod_Instance(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "instance_method",
			FilePath: "/app/UserController.php",
			Content: `<?php
namespace App\Controllers;

class UserController {
    public function show(int $id) {
        return $id;
    }
}
`,
			Func: `App\Controllers\UserController::show`,
			WantParams: []ParamTaint{
				{Index: 0, Name: "$id", Type: "int", CanonicalType: "int"},
			},
		},
	}
	RunHarness(t, rules.LangPHP, cases)
}

// TestPHPExtractor_ClassMethod_Static: static method emits with the same
// "Cls::method" naming as an instance method (PHP doesn't distinguish in
// the FuncNode ID).
func TestPHPExtractor_ClassMethod_Static(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "static_method",
			FilePath: "/app/UserController.php",
			Content: `<?php
namespace App\Controllers;

class UserController {
    public static function find($id) {
        return null;
    }
}
`,
			Func: `App\Controllers\UserController::find`,
			WantParams: []ParamTaint{
				{Index: 0, Name: "$id"},
			},
		},
	}
	RunHarness(t, rules.LangPHP, cases)
}

// TestPHPExtractor_Closure_AssignedToVariable: `$cb = function() use ()
// { ... };` becomes a FuncNode named "$cb" (qualified with the
// namespace).
func TestPHPExtractor_Closure_AssignedToVariable(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "closure_assigned_to_variable",
			FilePath: "/app/closure.php",
			Content: `<?php
namespace App;

$cb = function($x) use ($state) { return $state + $x; };
`,
			Func: `App\$cb`,
			WantParams: []ParamTaint{
				{Index: 0, Name: "$x"},
			},
		},
	}
	RunHarness(t, rules.LangPHP, cases)
}

// TestPHPExtractor_ArrowFunction_AssignedToVariable: `$cb = fn($x) => $x
// * 2;` (PHP 7.4+) becomes a FuncNode named "$cb".
func TestPHPExtractor_ArrowFunction_AssignedToVariable(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "arrow_function_assigned_to_variable",
			FilePath: "/app/arrow.php",
			Content: `<?php
namespace App;

$cb = fn($x) => $x * 2;
`,
			Func: `App\$cb`,
			WantParams: []ParamTaint{
				{Index: 0, Name: "$x"},
			},
		},
	}
	RunHarness(t, rules.LangPHP, cases)
}

// TestPHPExtractor_RouteClosure: `Route::get('/x', function() { ... })` —
// the closure argument becomes a synthetic FuncNode named after the
// callee method ("get@<line>") so the cross-file framework can reach it.
func TestPHPExtractor_RouteClosure(t *testing.T) {
	src := `<?php
namespace App;

Route::get('/u/{id}', function($id) { return $id; });
`
	ex := GetExtractor(rules.LangPHP)
	if ex == nil {
		t.Fatal("PHP extractor not registered")
	}
	ctx := &ExtractContext{
		FilePath: "/app/routes.php",
		Content:  []byte(src),
		Language: rules.LangPHP,
	}
	sigs := ex.ExtractFunctions(ctx)
	// Expect a signature whose name contains "get@" — the synthetic name
	// uses the route method (get) + line number for uniqueness.
	found := false
	for _, s := range sigs {
		if s.IsClosure && strings.Contains(s.Name, "get@") {
			found = true
			if len(s.Params) != 1 || s.Params[0].Name != "$id" {
				t.Errorf("Route closure params = %+v, want [{Name: $id}]", s.Params)
			}
			break
		}
	}
	if !found {
		var names []string
		for _, s := range sigs {
			names = append(names, s.Name)
		}
		t.Errorf("Route closure signature not emitted; sigs=%v", names)
	}
}

// TestPHPExtractor_InterfaceMethod_NoNode: methods in an interface have
// no body and should NOT be emitted as FuncSignatures.
func TestPHPExtractor_InterfaceMethod_NoNode(t *testing.T) {
	src := `<?php
namespace App;

interface I {
    public function process($x);
}

class Impl implements I {
    public function process($x) { return $x; }
}
`
	ex := GetExtractor(rules.LangPHP)
	if ex == nil {
		t.Fatal("PHP extractor not registered")
	}
	ctx := &ExtractContext{
		FilePath: "/app/i.php",
		Content:  []byte(src),
		Language: rules.LangPHP,
	}
	sigs := ex.ExtractFunctions(ctx)
	// The interface method should NOT be in sigs; the impl SHOULD be.
	var implFound, ifaceFound bool
	for _, s := range sigs {
		switch s.Name {
		case `App\Impl::process`:
			implFound = true
		case `App\I::process`:
			ifaceFound = true
		}
	}
	if !implFound {
		t.Error("App\\Impl::process not emitted")
	}
	if ifaceFound {
		t.Error("App\\I::process should NOT be emitted (no body)")
	}
}

// TestPHPExtractor_AbstractMethod_NoNode: abstract methods in an abstract
// class should be skipped, but concrete methods should still emit.
func TestPHPExtractor_AbstractMethod_NoNode(t *testing.T) {
	src := `<?php
namespace App;

abstract class A {
    abstract public function run();
    public function helper() { return 1; }
}
`
	ex := GetExtractor(rules.LangPHP)
	if ex == nil {
		t.Fatal("PHP extractor not registered")
	}
	ctx := &ExtractContext{
		FilePath: "/app/a.php",
		Content:  []byte(src),
		Language: rules.LangPHP,
	}
	sigs := ex.ExtractFunctions(ctx)
	var helperFound, runFound bool
	for _, s := range sigs {
		switch s.Name {
		case `App\A::helper`:
			helperFound = true
		case `App\A::run`:
			runFound = true
		}
	}
	if !helperFound {
		t.Error("concrete method App\\A::helper not emitted")
	}
	if runFound {
		t.Error("abstract method App\\A::run should NOT be emitted")
	}
}

// TestPHPExtractor_NoNamespace_TopLevelFunction: a file without
// `namespace ...;` still emits the top-level function under the bare
// name (no qualifier).
func TestPHPExtractor_NoNamespace_TopLevelFunction(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "bare_top_level_function",
			FilePath: "/app/global.php",
			Content: `<?php
function greet($name) {
    return "hi " . $name;
}
`,
			Func: "greet",
			WantParams: []ParamTaint{
				{Index: 0, Name: "$name"},
			},
		},
	}
	RunHarness(t, rules.LangPHP, cases)
}

// TestPHPExtractor_GroupedUse_DoesNotEmitSignatures verifies the
// extractor doesn't crash on a file with grouped `use` declarations.
// Grouped use is handled by the resolver's ExtractScope, not the
// signature extractor; this is a smoke test.
func TestPHPExtractor_GroupedUse_DoesNotEmitSignatures(t *testing.T) {
	src := `<?php
namespace App;

use App\Util\{Helper, Logger as L};

class C { public function m() { return 1; } }
`
	ex := GetExtractor(rules.LangPHP)
	if ex == nil {
		t.Fatal("PHP extractor not registered")
	}
	ctx := &ExtractContext{
		FilePath: "/app/c.php",
		Content:  []byte(src),
		Language: rules.LangPHP,
	}
	sigs := ex.ExtractFunctions(ctx)
	found := false
	for _, s := range sigs {
		if s.Name == `App\C::m` {
			found = true
			break
		}
	}
	if !found {
		t.Error("App\\C::m not emitted after grouped use")
	}
}

