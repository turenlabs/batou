package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"

	// Register taint catalogs (PHP sinks/sources).
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// hasNoSQLFlow reports whether any taint flow reached a CWE-943 NoSQL sink.
func hasNoSQLFlow(flows []taint.TaintFlow) bool {
	for _, f := range flows {
		if f.Sink.Category == taint.SnkNoSQL {
			return true
		}
	}
	return false
}

// TestArgShapeGate_PHPMongoFind is the load-bearing end-to-end assertion for
// SLICE 1: the MongoDB container-filter form fires CWE-943, while the Laravel
// Eloquent scalar-primary-key forms do not.
func TestArgShapeGate_PHPMongoFind(t *testing.T) {
	t.Run("container_filter_fires", func(t *testing.T) {
		// Array-literal filter carrying a tainted value — genuine NoSQL
		// injection. The container arg shape is preserved (recall).
		code := `<?php
$x = $_GET['q'];
$collection->find(['$where' => $x]);
`
		flows := Analyze(code, "/app/handler.php", rules.LangPHP)
		if !hasNoSQLFlow(flows) {
			t.Fatalf("expected CWE-943 NoSQL flow for find(['$where'=>$tainted]); got none: %+v", flows)
		}
	})

	t.Run("superglobal_subscript_var_fires", func(t *testing.T) {
		// Recall: a whole request value used as the filter
		// (`$filter = $_POST['filter']; find($filter)`) is the canonical
		// MongoDB NoSQL-injection shape — a request superglobal subscript can
		// itself be an array (`filter[$where]=…`). Structurally identical to a
		// scalar PK var, so it is intentionally KEPT (firing) for recall; the
		// Eloquent FP cluster is dropped by its non-subscript shapes instead.
		code := `<?php
$filter = $_POST['filter'];
$collection->find($filter);
`
		flows := Analyze(code, "/app/handler.php", rules.LangPHP)
		if !hasNoSQLFlow(flows) {
			t.Fatalf("expected CWE-943 NoSQL flow for find($_POST-backed filter); got none: %+v", flows)
		}
	})

	t.Run("foreach_value_pk_does_not_fire", func(t *testing.T) {
		// The bagisto FP cluster: a scalar primary key iterated out of a
		// request array and passed to Eloquent find(). $sid is tainted but is a
		// scalar element — Eloquent parameterizes it. Must NOT fire.
		code := `<?php
$ids = $_POST['ids'];
foreach ($ids as $sid) {
    $repo->find($sid);
}
`
		flows := Analyze(code, "/app/handler.php", rules.LangPHP)
		if hasNoSQLFlow(flows) {
			t.Fatalf("did NOT expect CWE-943 NoSQL flow for foreach find($scalarId); got: %+v", flows)
		}
	})

	t.Run("scalar_literal_pk_does_not_fire", func(t *testing.T) {
		code := `<?php
$repo->find(1);
`
		flows := Analyze(code, "/app/handler.php", rules.LangPHP)
		if hasNoSQLFlow(flows) {
			t.Fatalf("did NOT expect CWE-943 NoSQL flow for find(1); got: %+v", flows)
		}
	})

	// The next three subtests carry a genuinely TAINTED scalar to find() — each
	// FIRES CWE-943 on the pre-gate baseline (verified by reverting the
	// php_sinks.go opt-in), so they prove the gate actively SUPPRESSES the
	// Eloquent-PK form rather than passing trivially.

	t.Run("tainted_request_call_does_not_fire", func(t *testing.T) {
		// The bagisto FP shape: find(request('id')) — request('key') returns a
		// scalar, not a query document.
		code := `<?php
$repo->find(request('customer_id'));
`
		flows := Analyze(code, "/app/handler.php", rules.LangPHP)
		if hasNoSQLFlow(flows) {
			t.Fatalf("did NOT expect CWE-943 NoSQL flow for find(request('id')); got: %+v", flows)
		}
	})

	t.Run("tainted_scalar_via_helper_does_not_fire", func(t *testing.T) {
		// $y is tainted but resolves to trim(...) — a scalar string helper.
		code := `<?php
$x = $_GET['k'];
$y = trim($x);
$repo->find($y);
`
		flows := Analyze(code, "/app/handler.php", rules.LangPHP)
		if hasNoSQLFlow(flows) {
			t.Fatalf("did NOT expect CWE-943 NoSQL flow for find(trim($tainted)); got: %+v", flows)
		}
	})

	t.Run("tainted_concat_scalar_does_not_fire", func(t *testing.T) {
		// String concatenation yields a scalar string, never a query document.
		code := `<?php
$x = $_GET['k'];
$repo->find($x . '');
`
		flows := Analyze(code, "/app/handler.php", rules.LangPHP)
		if hasNoSQLFlow(flows) {
			t.Fatalf("did NOT expect CWE-943 NoSQL flow for find($tainted . ''); got: %+v", flows)
		}
	})

	t.Run("scalar_param_pk_does_not_fire", func(t *testing.T) {
		// $id arrives as a bare (untyped) function parameter — the dominant
		// real-world Eloquent controller shape (the bagisto FP cluster).
		code := `<?php
function show($request, $id) {
    $r = request('id');
    return $this->repo->find($id);
}
`
		flows := Analyze(code, "/app/handler.php", rules.LangPHP)
		if hasNoSQLFlow(flows) {
			t.Fatalf("did NOT expect CWE-943 NoSQL flow for find($paramId); got: %+v", flows)
		}
	})
}

// phpFindCallNode parses PHP and returns the first `->find(...)` member-call
// node, plus the php config. Used to drive the gate decision directly.
func phpFindCallNode(t *testing.T, code string) (*ast.Node, *langConfig) {
	t.Helper()
	tree := ast.Parse([]byte(code), rules.LangPHP)
	if tree == nil {
		t.Fatal("nil tree")
	}
	var found *ast.Node
	var walk func(n *ast.Node)
	walk = func(n *ast.Node) {
		if n == nil || found != nil {
			return
		}
		if n.Type() == "member_call_expression" {
			if nm := n.ChildByFieldName("name"); nm != nil && nm.Text() == "find" {
				found = n
				return
			}
		}
		for i := 0; i < n.ChildCount(); i++ {
			walk(n.Child(i))
		}
	}
	walk(tree.Root())
	if found == nil {
		t.Fatalf("no ->find(...) call found in:\n%s", code)
	}
	return found, phpConfig()
}

// TestArgShapeGate_Decision unit-tests the gate's KEEP/DROP verdict directly,
// independent of taint-propagation reachability. It pins both the precision
// (scalar forms DROP) and the recall-preserving (container forms KEEP) sides
// of the ArgShapeContainer gate.
func TestArgShapeGate_Decision(t *testing.T) {
	containerSink := &taint.SinkDef{
		ID:               "php.mongodb.find",
		Category:         taint.SnkNoSQL,
		Language:         rules.LangPHP,
		MethodName:       "find",
		DangerousArgs:    []int{0},
		RequiresArgShape: taint.ArgShapeContainer,
	}
	anySink := &taint.SinkDef{
		ID:            "php.eloquent.find",
		Category:      taint.SnkNoSQL,
		Language:      rules.LangPHP,
		MethodName:    "find",
		DangerousArgs: []int{0},
		// RequiresArgShape defaults to ArgShapeAny.
	}

	keep := []struct {
		name string
		code string
	}{
		{"array_literal", `<?php $c->find(['$where' => $x]);`},
		{"array_call", `<?php $c->find(array('a' => $x));`},
		{"json_decode_var", `<?php $q = json_decode($body, true); $c->find($q);`},
		{"array_literal_var", `<?php $f = ['a' => $x]; $c->find($f);`},
		{"array_typed_param", `<?php function r(array $f) { return $c->find($f); }`},
		{"iterable_typed_param", `<?php function r(iterable $f) { return $c->find($f); }`},
		{"array_merge_var", `<?php $f = array_merge($a, $b); $c->find($f);`},
		{"cast_array", `<?php $c->find((array) $x);`},
		// Subscript / element access can yield an array in PHP (request
		// superglobals carry nested arrays) — kept for NoSQL-injection recall.
		{"subscript_superglobal", `<?php $c->find($_POST['filter']);`},
		{"subscript_local", `<?php $c->find($data['order_id']);`},
		{"var_from_superglobal_subscript", `<?php $f = $_POST['filter']; $c->find($f);`},
	}
	for _, tc := range keep {
		t.Run("keep/"+tc.name, func(t *testing.T) {
			call, cfg := phpFindCallNode(t, tc.code)
			if !argShapeGateOK(call, containerSink, cfg) {
				t.Errorf("expected KEEP (container shape) for %q", tc.code)
			}
		})
	}

	drop := []struct {
		name string
		code string
	}{
		{"scalar_literal_int", `<?php $c->find(1);`},
		{"scalar_literal_string", `<?php $c->find("abc");`},
		{"bare_var_scalar_literal", `<?php $id = 5; $c->find($id);`},
		{"property_access", `<?php $c->find($invoice->order_id);`},
		{"var_from_property", `<?php $id = $invoice->order_id; $c->find($id);`},
		{"scalar_request_call", `<?php $c->find(request('customer_id'));`},
		{"scalar_method_call", `<?php $id = core()->getConfigData('x'); $c->find($id);`},
		{"foreach_value", `<?php foreach ($ids as $sid) { $c->find($sid); }`},
		{"untyped_param", `<?php function r($id) { return $c->find($id); }`},
		{"string_typed_param", `<?php function r(string $id) { return $c->find($id); }`},
	}
	for _, tc := range drop {
		t.Run("drop/"+tc.name, func(t *testing.T) {
			call, cfg := phpFindCallNode(t, tc.code)
			if argShapeGateOK(call, containerSink, cfg) {
				t.Errorf("expected DROP (scalar shape) for %q", tc.code)
			}
		})
	}

	// Default-zero RequiresArgShape (ArgShapeAny) must be a strict no-op: even
	// a provably-scalar arg keeps the candidate, proving byte-identical
	// behaviour for every sink that did not opt in.
	t.Run("any_shape_is_noop", func(t *testing.T) {
		call, cfg := phpFindCallNode(t, `<?php $c->find(1);`)
		if !argShapeGateOK(call, anySink, cfg) {
			t.Error("ArgShapeAny must never drop a candidate (no-op)")
		}
	})
}
