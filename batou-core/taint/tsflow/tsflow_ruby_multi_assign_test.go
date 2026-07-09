package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// Ruby parallel/multiple assignment (`a, b = ...`) recall-FN regression tests.
//
// Before the processRubyMultiAssign walker branch, the LHS of a Ruby
// multiple-assignment is a `left_assignment_list`, for which extractAssignLHS
// returns "" — so every parallel-assigned target silently lost its taint and
// downstream sinks produced zero flows. These tests pin the fix and its
// element-wise precision (only the target bound to the tainted element is
// flagged).

// --- Positive: taint must flow through the parallel-assigned target ---

func TestRuby_MultiAssign_ListElems_Command(t *testing.T) {
	// a, b = tainted, safe   (right_assignment_list, element-wise)
	code := `
def handler(params)
  a, b = params[:cmd], "safe"
  system(a)
end
`
	flows := Analyze(code, "/app/h.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for a = params[:cmd] via parallel assignment")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRuby_MultiAssign_ArrayLiteral_Command(t *testing.T) {
	// a, b = [tainted, safe]   (array literal RHS, element-wise)
	code := `
def handler(params)
  a, b = [params[:cmd], "x"]
  system(a)
end
`
	flows := Analyze(code, "/app/h.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for a from array-literal parallel assignment")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRuby_MultiAssign_SecondTarget_SQL(t *testing.T) {
	// a, b = safe, tainted   (element-wise binds the tainted element to b)
	code := `
require "mysql2"
def handler(params, client)
  a, b = "safe", params[:q]
  client.query(b)
end
`
	flows := Analyze(code, "/app/h.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for b = params[:q] via parallel assignment")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRuby_MultiAssign_WholeRHS_FromMethod_Command(t *testing.T) {
	// a, b = tainted_array   (non-literal RHS → conservative whole-RHS taint)
	code := `
def handler(params)
  parts = params[:cmd].split(",")
  a, b = parts
  system(a)
end
`
	flows := Analyze(code, "/app/h.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for a via whole-RHS multiple assignment")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRuby_MultiAssign_Splat_Command(t *testing.T) {
	// first, *rest = tainted, ...   (splat target; arity mismatch → whole-RHS)
	code := `
def handler(params)
  first, *rest = params[:cmd], "a", "b"
  system(first)
end
`
	flows := Analyze(code, "/app/h.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for first via splat multiple assignment")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Negative: element-wise precision must NOT over-taint the safe target ---

func TestRuby_MultiAssign_SafeTarget_NoFlow(t *testing.T) {
	// a, b = tainted, safe ; sink uses ONLY the safe target b → no flow.
	code := `
def handler(params)
  a, b = params[:cmd], "constant"
  system(b)
end
`
	flows := Analyze(code, "/app/h.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("did not expect command-injection flow — b is bound to a constant element")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRuby_MultiAssign_AllConstant_NoFlow(t *testing.T) {
	// a, b = safe, safe → no flow regardless of which target the sink reads.
	code := `
def handler
  a, b = "one", "two"
  system(a)
  system(b)
end
`
	flows := Analyze(code, "/app/h.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("did not expect any flow — both targets are constants")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
