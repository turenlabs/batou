package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// PHP extract() member/scoped-call disambiguation (CWE-621). The global
// extract($arr) injects array keys into the local symbol table (variable
// injection). But `->extract()` / `::extract()` is an extremely common
// framework method that returns field values and never touches local scope —
// Cake's `$entity->extract([...])` / `$node->extract($fields)`,
// `Hash::extract(...)`, Collection `->extract()`. Those member/scoped calls
// are a same-name collision with the global sink, not the sink itself, so they
// must NOT produce a CWE-621 flow, while the genuine global form must still fire.
//
// Real-repo FP cluster: cakephp src/ORM/Behavior/TreeBehavior.php (585/630/659/
// 719/748), src/ORM/Table.php:2618 — `$node->extract($fields)` /
// `$entity->extract($primaryKey)`, all block-eligible (conf 1.0) false positives.

func TestPHP_Extract_MemberScopedCall_NoInjection(t *testing.T) {
	cases := []struct {
		name string
		expr string
	}{
		{"member_call", `$result = $node->extract($value);`},
		{"member_call_chain", `$out = $this->_table->extract($value);`},
		{"scoped_call", `$out = Hash::extract($value, 'a.b');`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// $value is tainted; a flow WOULD exist if the member/scoped call
			// matched the global extract() sink. The call shape is what suppresses it.
			code := "<?php\nfunction handler() {\n    $value = $_GET[\"v\"];\n    " + c.expr + "\n}\n?>"
			flows := Analyze(code, "/app/handler.php", rules.LangPHP)
			if hasTaintFlowCWE(flows, "CWE-621") {
				t.Errorf("member/scoped extract (%s) must NOT fire CWE-621 variable injection (false positive)", c.expr)
				for _, f := range flows {
					t.Logf("  unexpected flow: %s -> %s (%s)", f.Source.Category, f.Sink.Category, f.Sink.CWEID)
				}
			}
		})
	}
}

// Positive: the genuine global extract($arr) variable-injection form still fires.
func TestPHP_Extract_GlobalForm_Fires(t *testing.T) {
	code := "<?php\nfunction handler() {\n    extract($_POST);\n}\n?>"
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlowCWE(flows, "CWE-621") {
		t.Errorf("global extract($_POST) MUST still fire CWE-621 variable injection (over-suppression)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%s)", f.Source.Category, f.Sink.Category, f.Sink.CWEID)
		}
	}
}
