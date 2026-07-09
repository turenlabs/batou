package tsflow

// Strong-update (last-write-wins) kill for JS/TS and Java.
//
// Batou's strong-update mechanism clears the taint of a bare identifier when it
// is UNCONDITIONALLY reassigned to an untainted value (`x = src; x = "safe";
// sink(x)` → no flow). Before this fix the kill was gated Python-only, so JS and
// Java false-fired on the canonical safe shape (UNSOUND_FP); Semgrep CE honours
// the kill in every language. These tests pin the lift to JS/TS/Java AND pin the
// two recall guards the Python gate already enforces:
//
//   - the kill fires ONLY on an UNCONDITIONAL plain `=` reassignment, so a
//     tainted value inside an `if`/`else` arm survives (may-taint preserved);
//   - linear-walked branch arms (JS/Java `switch`) are branch boundaries, so a
//     tainted switch arm survives a later literal arm (the documented hazard
//     that motivates the unconditional-only gate);
//   - augmented assignment (`x += ...`) reads its own prior value, so an
//     untainted RHS does NOT clear accumulated taint (Java spells `+=` as the
//     same node type as `=`, distinguished only by the operator field).
//
// See walker.go: branchBoundaryTypesFor / supportsStrongUpdate /
// isUnconditionalAssign / isPlainAssignNode and the kill site in
// processAssignInterproc.

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// --- JS ----------------------------------------------------------------------

// Negative (the FP fix): a var declaration tainted then unconditionally
// reassigned to a literal must NOT flow to the sink.
func TestJS_StrongUpdate_KillAfterDecl_NoFlow(t *testing.T) {
	code := `function h(req){ var x = req.params.name; x = "safe"; fs.readFile(x); }`
	flows := Analyze(code, "/app/h.js", rules.LangJavaScript)
	if hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Errorf("JS `var x = src; x = \"safe\"; sink(x)` must NOT flow (strong update)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// Negative (the FP fix, prior set by a bare reassignment rather than a decl).
func TestJS_StrongUpdate_KillAfterBareReassign_NoFlow(t *testing.T) {
	code := `function h(req){ var x; x = req.params.name; x = "safe"; fs.readFile(x); }`
	flows := Analyze(code, "/app/h.js", rules.LangJavaScript)
	if hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Errorf("JS `x = src; x = \"safe\"; sink(x)` must NOT flow (strong update)")
	}
}

// Positive (TPR guard): no reassignment — the single tainted decl must flow.
func TestJS_StrongUpdate_Baseline_Flows(t *testing.T) {
	code := `function h(req){ var x = req.params.name; fs.readFile(x); }`
	flows := Analyze(code, "/app/h.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Errorf("JS `var x = src; sink(x)` MUST flow (baseline recall guard)")
	}
}

// Positive (TPR guard, the unconditional-only gate): a CONDITIONAL tainted arm
// (`else { x = src }`) must survive — the literal arm is conditional so it
// cannot clear it, and may-taint is preserved.
func TestJS_StrongUpdate_CondTaint_StillFlows(t *testing.T) {
	code := `function h(req,c){ var x = "safe"; if(c){ x="ok"; } else { x=req.params.name; } fs.readFile(x); }`
	flows := Analyze(code, "/app/h.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Errorf("JS conditionally-tainted `else { x = src }` MUST still flow (may-taint)")
	}
}

// Positive (TPR guard, linear-walk hazard): a tainted `switch` arm followed by a
// later literal arm must survive — switch arms are walked linearly without a
// branch-merge, so they are branch boundaries.
func TestJS_StrongUpdate_SwitchArm_StillFlows(t *testing.T) {
	code := `function h(req,k){ var x; switch(k){ case 1: x=req.params.name; break; case 2: x="safe"; break; } fs.readFile(x); }`
	flows := Analyze(code, "/app/h.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Errorf("JS tainted switch arm MUST survive a later literal arm (linear-walk hazard)")
	}
}

// --- TS (shares the JS config) -----------------------------------------------

func TestTS_StrongUpdate_Kill_NoFlow(t *testing.T) {
	code := `function h(req: any){ let x = req.params.name; x = "safe"; fs.readFile(x); }`
	flows := Analyze(code, "/app/h.ts", rules.LangTypeScript)
	if hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Errorf("TS `let x = src; x = \"safe\"; sink(x)` must NOT flow (strong update)")
	}
}

// --- Java --------------------------------------------------------------------

func TestJava_StrongUpdate_Kill_NoFlow(t *testing.T) {
	code := `public class A { void h(HttpServletRequest request) {
 String x = request.getParameter("c");
 x = "safe";
 Runtime.getRuntime().exec(x);
} }
`
	flows := Analyze(code, "/app/A.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Errorf("Java `String x = src; x = \"safe\"; exec(x)` must NOT flow (strong update)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestJava_StrongUpdate_Baseline_Flows(t *testing.T) {
	code := `public class A { void h(HttpServletRequest request) {
 String x = request.getParameter("c");
 Runtime.getRuntime().exec(x);
} }
`
	flows := Analyze(code, "/app/A.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Errorf("Java `String x = src; exec(x)` MUST flow (baseline recall guard)")
	}
}

func TestJava_StrongUpdate_CondTaint_StillFlows(t *testing.T) {
	code := `public class A { void h(HttpServletRequest request, boolean c) {
 String x = "safe";
 if(c){ x="ok"; } else { x=request.getParameter("c"); }
 Runtime.getRuntime().exec(x);
} }
`
	flows := Analyze(code, "/app/A.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Errorf("Java conditionally-tainted `else { x = src }` MUST still flow (may-taint)")
	}
}

// Positive (TPR guard, linear-walk hazard): classic Java `switch` arms are
// switch_block_statement_group nodes, walked linearly — a tainted arm must
// survive a later literal arm.
func TestJava_StrongUpdate_SwitchArm_StillFlows(t *testing.T) {
	code := `public class A { void h(HttpServletRequest request, int k) {
 String x = "";
 switch(k){ case 1: x=request.getParameter("c"); break; case 2: x="safe"; break; }
 Runtime.getRuntime().exec(x);
} }
`
	flows := Analyze(code, "/app/A.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Errorf("Java tainted switch arm MUST survive a later literal arm (linear-walk hazard)")
	}
}

// Positive (TPR guard, augmented assignment): `x += src` then `x += "literal"`
// must keep the accumulated taint. Java spells `+=` with the same
// assignment_expression node type as `=`, so the operator field must gate the
// kill (isPlainAssignNode) — otherwise the literal `+=` would wrongly clear it.
func TestJava_StrongUpdate_AugmentedAccum_StillFlows(t *testing.T) {
	code := `public class A { void h(HttpServletRequest request) {
 String x = "";
 x += request.getParameter("c");
 x += "literal";
 Runtime.getRuntime().exec(x);
} }
`
	flows := Analyze(code, "/app/A.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Errorf("Java `x += src; x += \"literal\"` MUST keep accumulated taint (augmented assign)")
	}
}

// --- Unsupported language guard ----------------------------------------------

// Ruby is NOT in supportsStrongUpdate, so the conservative may-taint behaviour
// is preserved: `x = src; x = "safe"; sink(x)` still flows (no kill). This pins
// that the lift is scoped to the three vetted languages and does not silently
// change every tsflow language.
func TestRuby_StrongUpdate_NotApplied_StillFlows(t *testing.T) {
	code := "def h\n  x = params[:c]\n  x = \"safe\"\n  system(x)\nend\n"
	flows := Analyze(code, "/app/h.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Errorf("Ruby (no strong-update support) must keep conservative may-taint flow")
	}
}
