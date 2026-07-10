package graph

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// TestPropagation_LiftsSinkAcrossOneHop verifies the simplest case:
// F(x) -> G(x) where G has SinkCalls{ArgFromParam: 0}. F should
// inherit a SinkRef with ArgFromParam pointing at F's param "x".
func TestPropagation_LiftsSinkAcrossOneHop(t *testing.T) {
	root := t.TempDir()
	if err := writeFiles(t, root, map[string]string{
		"a/a.go": "package a\n\nfunc F(x string) {\n\tG(x)\n}\n",
	}); err != nil {
		t.Fatal(err)
	}
	aPath := filepath.Join(root, "a/a.go")
	bPath := filepath.Join(root, "b/b.go")

	cg := NewCallGraph(root, "test")
	cg.AddNode(&FuncNode{
		ID:        aPath + ":F",
		FilePath:  aPath,
		Name:      "F",
		Language:  rules.LangGo,
		StartLine: 3,
		EndLine:   5,
		Calls:     []string{bPath + ":G"},
		TaintSig: TaintSignature{
			Params: []ParamTaint{{Index: 0, Name: "x"}},
		},
	})
	cg.AddNode(&FuncNode{
		ID:       bPath + ":G",
		FilePath: bPath,
		Name:     "G",
		Language: rules.LangGo,
		TaintSig: TaintSignature{
			SinkCalls: []SinkRef{{SinkCategory: taint.SnkHTMLOutput, MethodName: "Write", Line: 5, ArgFromParam: 0}},
		},
	})

	stats := PropagateSignaturesAcrossCallgraph(cg, nil)
	if stats.SinksLifted != 1 {
		t.Errorf("SinksLifted = %d, want 1 (stats=%+v)", stats.SinksLifted, stats)
	}
	node := cg.GetNode(aPath + ":F")
	if len(node.TaintSig.SinkCalls) != 1 {
		t.Fatalf("F.SinkCalls = %v, want 1 entry", node.TaintSig.SinkCalls)
	}
	if node.TaintSig.SinkCalls[0].ArgFromParam != 0 {
		t.Errorf("F.SinkCalls[0].ArgFromParam = %d, want 0", node.TaintSig.SinkCalls[0].ArgFromParam)
	}
	if node.TaintSig.SinkCalls[0].SinkCategory != taint.SnkHTMLOutput {
		t.Errorf("F.SinkCalls[0].SinkCategory = %v, want SnkHTMLOutput", node.TaintSig.SinkCalls[0].SinkCategory)
	}
}

// derivePropagationCase builds F(p) -> G(<argExpr>) with G holding a sink at
// param 0, runs the propagation pass, and returns how many sinks were lifted
// into F. It exercises matchDerivedParamName (the one-transform recall fix).
func derivePropagationCase(t *testing.T, argExpr string) int {
	t.Helper()
	root := t.TempDir()
	if err := writeFiles(t, root, map[string]string{
		"a/a.go": "package a\n\nfunc F(p string) {\n\tG(" + argExpr + ")\n}\n",
	}); err != nil {
		t.Fatal(err)
	}
	aPath := filepath.Join(root, "a/a.go")
	bPath := filepath.Join(root, "b/b.go")
	cg := NewCallGraph(root, "test")
	cg.AddNode(&FuncNode{
		ID: aPath + ":F", FilePath: aPath, Name: "F", Language: rules.LangGo,
		StartLine: 3, EndLine: 5, Calls: []string{bPath + ":G"},
		TaintSig: TaintSignature{Params: []ParamTaint{{Index: 0, Name: "p"}}},
	})
	cg.AddNode(&FuncNode{
		ID: bPath + ":G", FilePath: bPath, Name: "G", Language: rules.LangGo,
		TaintSig: TaintSignature{
			SinkCalls: []SinkRef{{SinkCategory: taint.SnkHTMLOutput, MethodName: "Write", Line: 5, ArgFromParam: 0}},
		},
	})
	return PropagateSignaturesAcrossCallgraph(cg, nil).SinksLifted
}

// TestPropagation_LiftsSinkThroughSingleArgTransform: F(p) -> G(parse(p)).
// Before matchDerivedParamName the reshaped arg "parse(p)" failed the bare-name
// gate and F inherited NO sink. Now F must inherit G's sink (parse(p) is
// derived-from-p) — the core recall-ceiling fix.
func TestPropagation_LiftsSinkThroughSingleArgTransform(t *testing.T) {
	if got := derivePropagationCase(t, "parse(p)"); got != 1 {
		t.Errorf("SinksLifted = %d, want 1 (sink(parse(p)) should lift)", got)
	}
}

// TestPropagation_LiftsSinkThroughMethodReceiver: F(p) -> G(p.trim()). The
// value flowing to the sink is derived from the receiver p.
func TestPropagation_LiftsSinkThroughMethodReceiver(t *testing.T) {
	if got := derivePropagationCase(t, "p.trim()"); got != 1 {
		t.Errorf("SinksLifted = %d, want 1 (sink(p.trim()) should lift via receiver)", got)
	}
}

// TestPropagation_SanitizerGuardBlocksLift: F(p) -> G(escape(p)) must NOT lift —
// escape is a sanitizer for the sink category, so the derived value is clean.
// This is the FPR-flat guarantee: derivation is recall-only, never over-firing
// through a sanitizing transform.
func TestPropagation_SanitizerGuardBlocksLift(t *testing.T) {
	if got := derivePropagationCase(t, "escape(p)"); got != 0 {
		t.Errorf("SinksLifted = %d, want 0 (sink(escape(p)) must be blocked by the sanitizer guard)", got)
	}
}

// TestPropagation_IdempotentOnSecondRun verifies running the pass twice
// does not duplicate inherited sinks.
func TestPropagation_IdempotentOnSecondRun(t *testing.T) {
	root := t.TempDir()
	if err := writeFiles(t, root, map[string]string{
		"a/a.go": "package a\n\nfunc F(x string) {\n\tG(x)\n}\n",
	}); err != nil {
		t.Fatal(err)
	}
	aPath := filepath.Join(root, "a/a.go")
	bPath := filepath.Join(root, "b/b.go")

	cg := NewCallGraph(root, "test")
	cg.AddNode(&FuncNode{
		ID: aPath + ":F", FilePath: aPath, Name: "F", Language: rules.LangGo,
		StartLine: 3, EndLine: 5, Calls: []string{bPath + ":G"},
		TaintSig: TaintSignature{Params: []ParamTaint{{Index: 0, Name: "x"}}},
	})
	cg.AddNode(&FuncNode{
		ID: bPath + ":G", FilePath: bPath, Name: "G", Language: rules.LangGo,
		TaintSig: TaintSignature{
			SinkCalls: []SinkRef{{SinkCategory: taint.SnkHTMLOutput, MethodName: "Write", Line: 5, ArgFromParam: 0}},
		},
	})

	_ = PropagateSignaturesAcrossCallgraph(cg, nil)
	beforeCount := len(cg.GetNode(aPath + ":F").TaintSig.SinkCalls)
	_ = PropagateSignaturesAcrossCallgraph(cg, nil)
	afterCount := len(cg.GetNode(aPath + ":F").TaintSig.SinkCalls)
	if beforeCount != afterCount {
		t.Errorf("propagation duplicated sinks: before=%d after=%d", beforeCount, afterCount)
	}
}

// TestPropagation_DoesNotMatchUnrelatedParam verifies the algorithm only
// propagates when the caller passes ONE OF ITS OWN PARAMETERS to the
// callee — not a fresh local or a derived expression.
func TestPropagation_DoesNotMatchUnrelatedParam(t *testing.T) {
	root := t.TempDir()
	if err := writeFiles(t, root, map[string]string{
		"a/a.go": "package a\n\nfunc F(x string) {\n\tlocal := \"hard-coded\"\n\tG(local)\n}\n",
	}); err != nil {
		t.Fatal(err)
	}
	aPath := filepath.Join(root, "a/a.go")
	bPath := filepath.Join(root, "b/b.go")

	cg := NewCallGraph(root, "test")
	cg.AddNode(&FuncNode{
		ID: aPath + ":F", FilePath: aPath, Name: "F", Language: rules.LangGo,
		StartLine: 3, EndLine: 6, Calls: []string{bPath + ":G"},
		TaintSig: TaintSignature{Params: []ParamTaint{{Index: 0, Name: "x"}}},
	})
	cg.AddNode(&FuncNode{
		ID: bPath + ":G", FilePath: bPath, Name: "G", Language: rules.LangGo,
		TaintSig: TaintSignature{
			SinkCalls: []SinkRef{{SinkCategory: taint.SnkHTMLOutput, MethodName: "Write", Line: 5, ArgFromParam: 0}},
		},
	})

	_ = PropagateSignaturesAcrossCallgraph(cg, nil)
	node := cg.GetNode(aPath + ":F")
	if len(node.TaintSig.SinkCalls) != 0 {
		t.Errorf("F should not have inherited a sink: got %v", node.TaintSig.SinkCalls)
	}
}

// TestPropagation_LiftsSinkAcrossOneHopPython mirrors the Go test but
// for Python. F(x) -> G(x) where G has a SinkCall at ArgFromParam=0.
// After propagation, F should inherit a SinkRef with OriginFile/Line
// pointing at G's actual sink call so cross-file finding rendering can
// preserve the leaf location even after multi-hop hoists.
func TestPropagation_LiftsSinkAcrossOneHopPython(t *testing.T) {
	root := t.TempDir()
	if err := writeFiles(t, root, map[string]string{
		"a.py": "def F(x):\n    G(x)\n",
	}); err != nil {
		t.Fatal(err)
	}
	aPath := filepath.Join(root, "a.py")
	bPath := filepath.Join(root, "b.py")

	cg := NewCallGraph(root, "test")
	cg.AddNode(&FuncNode{
		ID:        aPath + ":F",
		FilePath:  aPath,
		Name:      "F",
		Language:  rules.LangPython,
		StartLine: 1,
		EndLine:   2,
		Calls:     []string{bPath + ":G"},
		TaintSig: TaintSignature{
			Params: []ParamTaint{{Index: 0, Name: "x"}},
		},
	})
	cg.AddNode(&FuncNode{
		ID:       bPath + ":G",
		FilePath: bPath,
		Name:     "G",
		Language: rules.LangPython,
		TaintSig: TaintSignature{
			SinkCalls: []SinkRef{{SinkCategory: taint.SnkCommand, MethodName: "subprocess.run", Line: 5, ArgFromParam: 0}},
		},
	})

	stats := PropagateSignaturesAcrossCallgraph(cg, nil)
	if stats.SinksLifted < 1 {
		t.Fatalf("expected at least 1 sink lifted, got %+v", stats)
	}
	node := cg.GetNode(aPath + ":F")
	if len(node.TaintSig.SinkCalls) != 1 {
		t.Fatalf("F.SinkCalls = %v, want 1 entry", node.TaintSig.SinkCalls)
	}
	lifted := node.TaintSig.SinkCalls[0]
	if lifted.ArgFromParam != 0 {
		t.Errorf("F.SinkCalls[0].ArgFromParam = %d, want 0", lifted.ArgFromParam)
	}
	if lifted.OriginFile != bPath {
		t.Errorf("F.SinkCalls[0].OriginFile = %q, want %q", lifted.OriginFile, bPath)
	}
	if lifted.OriginLine != 5 {
		t.Errorf("F.SinkCalls[0].OriginLine = %d, want 5 (G's sink line)", lifted.OriginLine)
	}
	if !strings.Contains(lifted.MethodName, "via G") {
		t.Errorf("F.SinkCalls[0].MethodName = %q, want it to mention \"via G\"", lifted.MethodName)
	}
}

// TestPropagation_ConvergesInFewIterationsPython mirrors the multi-hop
// Go test for Python: F(x) -> G(x) -> H(x) sink. After propagation, F
// gains the sink with OriginFile preserved through both hops so cross-
// file rendering still points at H's file.
func TestPropagation_ConvergesInFewIterationsPython(t *testing.T) {
	root := t.TempDir()
	if err := writeFiles(t, root, map[string]string{
		"a.py": "def F(x):\n    G(x)\n",
		"b.py": "def G(x):\n    H(x)\n",
	}); err != nil {
		t.Fatal(err)
	}
	aPath := filepath.Join(root, "a.py")
	bPath := filepath.Join(root, "b.py")
	cPath := filepath.Join(root, "c.py")

	cg := NewCallGraph(root, "test")
	cg.AddNode(&FuncNode{
		ID: aPath + ":F", FilePath: aPath, Name: "F", Language: rules.LangPython,
		StartLine: 1, EndLine: 2, Calls: []string{bPath + ":G"},
		TaintSig: TaintSignature{Params: []ParamTaint{{Index: 0, Name: "x"}}},
	})
	cg.AddNode(&FuncNode{
		ID: bPath + ":G", FilePath: bPath, Name: "G", Language: rules.LangPython,
		StartLine: 1, EndLine: 2, Calls: []string{cPath + ":H"},
		TaintSig: TaintSignature{Params: []ParamTaint{{Index: 0, Name: "x"}}},
	})
	cg.AddNode(&FuncNode{
		ID: cPath + ":H", FilePath: cPath, Name: "H", Language: rules.LangPython,
		TaintSig: TaintSignature{
			SinkCalls: []SinkRef{{SinkCategory: taint.SnkCommand, MethodName: "subprocess.run", Line: 5, ArgFromParam: 0}},
		},
	})

	stats := PropagateSignaturesAcrossCallgraph(cg, nil)
	if stats.SinksLifted != 2 {
		t.Errorf("SinksLifted = %d, want 2 (H->G + G->F)", stats.SinksLifted)
	}
	fSinks := cg.GetNode(aPath + ":F").TaintSig.SinkCalls
	if len(fSinks) != 1 {
		t.Fatalf("F did not inherit the sink: %v", fSinks)
	}
	if fSinks[0].OriginFile != cPath {
		t.Errorf("F.SinkCalls[0].OriginFile = %q after 2-hop lift, want %q (H's file)", fSinks[0].OriginFile, cPath)
	}
	if fSinks[0].OriginLine != 5 {
		t.Errorf("F.SinkCalls[0].OriginLine = %d, want 5 (preserved from H)", fSinks[0].OriginLine)
	}
}

// TestPropagation_IdempotentOnSecondRunPython verifies that running
// Python propagation twice doesn't duplicate inherited sinks.
func TestPropagation_IdempotentOnSecondRunPython(t *testing.T) {
	root := t.TempDir()
	if err := writeFiles(t, root, map[string]string{
		"a.py": "def F(x):\n    G(x)\n",
	}); err != nil {
		t.Fatal(err)
	}
	aPath := filepath.Join(root, "a.py")
	bPath := filepath.Join(root, "b.py")

	cg := NewCallGraph(root, "test")
	cg.AddNode(&FuncNode{
		ID: aPath + ":F", FilePath: aPath, Name: "F", Language: rules.LangPython,
		StartLine: 1, EndLine: 2, Calls: []string{bPath + ":G"},
		TaintSig: TaintSignature{Params: []ParamTaint{{Index: 0, Name: "x"}}},
	})
	cg.AddNode(&FuncNode{
		ID: bPath + ":G", FilePath: bPath, Name: "G", Language: rules.LangPython,
		TaintSig: TaintSignature{
			SinkCalls: []SinkRef{{SinkCategory: taint.SnkCommand, MethodName: "subprocess.run", Line: 5, ArgFromParam: 0}},
		},
	})

	_ = PropagateSignaturesAcrossCallgraph(cg, nil)
	beforeCount := len(cg.GetNode(aPath + ":F").TaintSig.SinkCalls)
	_ = PropagateSignaturesAcrossCallgraph(cg, nil)
	afterCount := len(cg.GetNode(aPath + ":F").TaintSig.SinkCalls)
	if beforeCount != afterCount {
		t.Errorf("Python propagation duplicated sinks: before=%d after=%d", beforeCount, afterCount)
	}
}

// TestPropagation_ConvergesInFewIterations verifies multi-hop chains
// (F→G→H sink) converge.
func TestPropagation_ConvergesInFewIterations(t *testing.T) {
	root := t.TempDir()
	if err := writeFiles(t, root, map[string]string{
		"a/a.go": "package a\n\nfunc F(x string) {\n\tG(x)\n}\n",
		"b/b.go": "package b\n\nfunc G(x string) {\n\tH(x)\n}\n",
	}); err != nil {
		t.Fatal(err)
	}
	aPath := filepath.Join(root, "a/a.go")
	bPath := filepath.Join(root, "b/b.go")
	cPath := filepath.Join(root, "c/c.go")

	cg := NewCallGraph(root, "test")
	cg.AddNode(&FuncNode{
		ID: aPath + ":F", FilePath: aPath, Name: "F", Language: rules.LangGo,
		StartLine: 3, EndLine: 5, Calls: []string{bPath + ":G"},
		TaintSig: TaintSignature{Params: []ParamTaint{{Index: 0, Name: "x"}}},
	})
	cg.AddNode(&FuncNode{
		ID: bPath + ":G", FilePath: bPath, Name: "G", Language: rules.LangGo,
		StartLine: 3, EndLine: 5, Calls: []string{cPath + ":H"},
		TaintSig: TaintSignature{Params: []ParamTaint{{Index: 0, Name: "x"}}},
	})
	cg.AddNode(&FuncNode{
		ID: cPath + ":H", FilePath: cPath, Name: "H", Language: rules.LangGo,
		TaintSig: TaintSignature{
			SinkCalls: []SinkRef{{SinkCategory: taint.SnkCommand, MethodName: "exec", Line: 5, ArgFromParam: 0}},
		},
	})

	stats := PropagateSignaturesAcrossCallgraph(cg, nil)
	// Two hops to lift the sink to F: H→G then G→F. So at least
	// 2 iterations + 1 no-change termination.
	if stats.Iterations < 2 || stats.Iterations > sigPropagationMaxIters {
		t.Errorf("Iterations = %d, want 2..%d", stats.Iterations, sigPropagationMaxIters)
	}
	if stats.SinksLifted != 2 {
		t.Errorf("SinksLifted = %d, want 2 (H→G + G→F)", stats.SinksLifted)
	}
	if len(cg.GetNode(aPath+":F").TaintSig.SinkCalls) != 1 {
		t.Errorf("F did not inherit the sink: %v", cg.GetNode(aPath+":F").TaintSig.SinkCalls)
	}
}

// TestPropagation_LiftsSinkThroughConcat: F(p) -> G("SELECT ... " + p). The
// canonical injection shape — concatenating a param into a string and forwarding
// it across a call boundary. One operand is param-derived, so the sink lifts.
func TestPropagation_LiftsSinkThroughConcat(t *testing.T) {
	if got := derivePropagationCase(t, `"SELECT * FROM t WHERE x=" + p`); got != 1 {
		t.Errorf("SinksLifted = %d, want 1 (concat with a literal should lift)", got)
	}
	if got := derivePropagationCase(t, `p + "/suffix"`); got != 1 {
		t.Errorf("SinksLifted = %d, want 1 (param + literal should lift)", got)
	}
}

// TestPropagation_ConcatNoParamNoLift: "a" + "b" (no param operand) must not lift.
func TestPropagation_ConcatNoParamNoLift(t *testing.T) {
	if got := derivePropagationCase(t, `"a" + "b"`); got != 0 {
		t.Errorf("SinksLifted = %d, want 0 (concat of two literals must not lift)", got)
	}
}

// TestPropagation_ConcatSanitizedOperandNoLift: "x" + escape(p) must not lift —
// the sanitizer guard applies to the escaped operand.
func TestPropagation_ConcatSanitizedOperandNoLift(t *testing.T) {
	if got := derivePropagationCase(t, `"x" + escape(p)`); got != 0 {
		t.Errorf("SinksLifted = %d, want 0 (concat of a sanitized operand must not lift)", got)
	}
}

// lookbackCase builds F(p) with a multi-line body and a final G(<callArg>),
// running propagation. Used to exercise the local-assignment lookback.
func lookbackCase(t *testing.T, bodyMid, callArg string) int {
	t.Helper()
	root := t.TempDir()
	src := "package a\n\nfunc F(p string) {\n" + bodyMid + "\tG(" + callArg + ")\n}\n"
	if err := writeFiles(t, root, map[string]string{"a/a.go": src}); err != nil {
		t.Fatal(err)
	}
	aPath := filepath.Join(root, "a/a.go")
	bPath := filepath.Join(root, "b/b.go")
	endLine := 3 + strings.Count(bodyMid, "\n") + 2
	cg := NewCallGraph(root, "test")
	cg.AddNode(&FuncNode{
		ID: aPath + ":F", FilePath: aPath, Name: "F", Language: rules.LangGo,
		StartLine: 3, EndLine: endLine, Calls: []string{bPath + ":G"},
		TaintSig: TaintSignature{Params: []ParamTaint{{Index: 0, Name: "p"}}},
	})
	cg.AddNode(&FuncNode{
		ID: bPath + ":G", FilePath: bPath, Name: "G", Language: rules.LangGo,
		TaintSig: TaintSignature{SinkCalls: []SinkRef{{SinkCategory: taint.SnkHTMLOutput, MethodName: "Write", Line: 5, ArgFromParam: 0}}},
	})
	return PropagateSignaturesAcrossCallgraph(cg, nil).SinksLifted
}

func TestPropagation_LiftsSinkThroughLocalAssignment(t *testing.T) {
	if got := lookbackCase(t, "\tq := build(p)\n", "q"); got != 1 {
		t.Errorf("SinksLifted = %d, want 1 (q := build(p); G(q) should lift)", got)
	}
}

func TestPropagation_LookbackUnrelatedNoLift(t *testing.T) {
	if got := lookbackCase(t, "\tq := unrelated()\n", "q"); got != 0 {
		t.Errorf("SinksLifted = %d, want 0 (q not derived from p must not lift)", got)
	}
}

// TestPropagation_LookbackCommentedBindingNoLift: a commented-out binding
// must never resurrect a flow — the lookback skips comment lines.
func TestPropagation_LookbackCommentedBindingNoLift(t *testing.T) {
	if got := lookbackCase(t, "\t// q := build(p)\n", "q"); got != 0 {
		t.Errorf("SinksLifted = %d, want 0 (commented-out binding must not lift)", got)
	}
}

// pythonLookbackCase is the Python analog of lookbackCase: builds F(p) with
// one local-rebind line and a final G(<callArg>), runs propagation, and
// returns SinksLifted. Exercises the Python wiring of the local-assignment
// lookback (real bodyLines/callLineIdx instead of nil/0).
func pythonLookbackCase(t *testing.T, bindLine, callArg string) int {
	t.Helper()
	root := t.TempDir()
	src := "def F(p):\n    " + bindLine + "\n    G(" + callArg + ")\n"
	if err := writeFiles(t, root, map[string]string{"a.py": src}); err != nil {
		t.Fatal(err)
	}
	aPath := filepath.Join(root, "a.py")
	bPath := filepath.Join(root, "b.py")
	cg := NewCallGraph(root, "test")
	cg.AddNode(&FuncNode{
		ID: aPath + ":F", FilePath: aPath, Name: "F", Language: rules.LangPython,
		StartLine: 1, EndLine: 3, Calls: []string{bPath + ":G"},
		TaintSig: TaintSignature{Params: []ParamTaint{{Index: 0, Name: "p"}}},
	})
	cg.AddNode(&FuncNode{
		ID: bPath + ":G", FilePath: bPath, Name: "G", Language: rules.LangPython,
		TaintSig: TaintSignature{
			SinkCalls: []SinkRef{{SinkCategory: taint.SnkCommand, MethodName: "subprocess.run", Line: 5, ArgFromParam: 0}},
		},
	})
	return PropagateSignaturesAcrossCallgraph(cg, nil).SinksLifted
}

// TestPropagation_PythonLookbackLiftsLocalAssignment: `q = build(p)` then
// G(q) must lift G's sink into F — the Python wiring of the lookback that
// previously passed nil bodyLines / 0 callLineIdx (so this never lifted).
func TestPropagation_PythonLookbackLiftsLocalAssignment(t *testing.T) {
	if got := pythonLookbackCase(t, "q = build(p)", "q"); got != 1 {
		t.Errorf("SinksLifted = %d, want 1 (q = build(p); G(q) should lift)", got)
	}
}

// TestPropagation_PythonLookbackSanitizerNoLift: a rebind THROUGH a
// sanitizer-named call must not lift — isSanitizerByName is consulted on
// the looked-back RHS exactly as in the Go path.
func TestPropagation_PythonLookbackSanitizerNoLift(t *testing.T) {
	if got := pythonLookbackCase(t, "q = escape(p)", "q"); got != 0 {
		t.Errorf("SinksLifted = %d, want 0 (q = escape(p); G(q) must not lift)", got)
	}
}

// TestPropagation_PythonLookbackUnrelatedNoLift: a binding not derived from
// any param must not lift.
func TestPropagation_PythonLookbackUnrelatedNoLift(t *testing.T) {
	if got := pythonLookbackCase(t, "q = unrelated()", "q"); got != 0 {
		t.Errorf("SinksLifted = %d, want 0 (q not derived from p must not lift)", got)
	}
}

// TestPropagation_PythonLookbackCommentedBindingNoLift: a commented-out
// Python binding (`# q = build(p)`) must not resurrect a flow.
func TestPropagation_PythonLookbackCommentedBindingNoLift(t *testing.T) {
	if got := pythonLookbackCase(t, "# q = build(p)", "q"); got != 0 {
		t.Errorf("SinksLifted = %d, want 0 (commented-out binding must not lift)", got)
	}
}

// jsLookbackCase is the JavaScript analog of lookbackCase: builds F(p) with
// one local-rebind line and a final G(<callArg>), runs propagation, and
// returns SinksLifted.
func jsLookbackCase(t *testing.T, bindLine, callArg string) int {
	t.Helper()
	root := t.TempDir()
	src := "function F(p) {\n    " + bindLine + "\n    G(" + callArg + ");\n}\n"
	if err := writeFiles(t, root, map[string]string{"a.js": src}); err != nil {
		t.Fatal(err)
	}
	aPath := filepath.Join(root, "a.js")
	bPath := filepath.Join(root, "b.js")
	cg := NewCallGraph(root, "test")
	cg.AddNode(&FuncNode{
		ID: aPath + ":F", FilePath: aPath, Name: "F", Language: rules.LangJavaScript,
		StartLine: 1, EndLine: 4, Calls: []string{bPath + ":G"},
		TaintSig: TaintSignature{Params: []ParamTaint{{Index: 0, Name: "p"}}},
	})
	cg.AddNode(&FuncNode{
		ID: bPath + ":G", FilePath: bPath, Name: "G", Language: rules.LangJavaScript,
		TaintSig: TaintSignature{
			SinkCalls: []SinkRef{{SinkCategory: taint.SnkCommand, MethodName: "child_process.exec", Line: 5, ArgFromParam: 0}},
		},
	})
	return PropagateSignaturesAcrossCallgraph(cg, nil).SinksLifted
}

// TestPropagation_JSLookbackLiftsConstBinding: `const q = build(p)` then
// G(q) must lift — the JS wiring of the local-assignment lookback.
func TestPropagation_JSLookbackLiftsConstBinding(t *testing.T) {
	if got := jsLookbackCase(t, "const q = build(p);", "q"); got != 1 {
		t.Errorf("SinksLifted = %d, want 1 (const q = build(p); G(q) should lift)", got)
	}
}

// TestPropagation_JSLookbackLiftsBareReassign: a bare reassign
// (`q = build(p)`) must lift too — same shape without a decl keyword.
func TestPropagation_JSLookbackLiftsBareReassign(t *testing.T) {
	if got := jsLookbackCase(t, "q = build(p);", "q"); got != 1 {
		t.Errorf("SinksLifted = %d, want 1 (q = build(p); G(q) should lift)", got)
	}
}

// TestPropagation_JSLookbackSanitizerNoLift: `let q = escape(p)` then G(q)
// must NOT lift — the sanitizer guard applies to the looked-back RHS.
func TestPropagation_JSLookbackSanitizerNoLift(t *testing.T) {
	if got := jsLookbackCase(t, "let q = escape(p);", "q"); got != 0 {
		t.Errorf("SinksLifted = %d, want 0 (let q = escape(p); G(q) must not lift)", got)
	}
}

// TestPropagation_JSLookbackUnrelatedNoLift: a binding not derived from any
// param must not lift.
func TestPropagation_JSLookbackUnrelatedNoLift(t *testing.T) {
	if got := jsLookbackCase(t, "const q = unrelated();", "q"); got != 0 {
		t.Errorf("SinksLifted = %d, want 0 (q not derived from p must not lift)", got)
	}
}
