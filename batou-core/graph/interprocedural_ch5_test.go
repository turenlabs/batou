package graph

import (
	"path/filepath"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// CH5: the regex-fallback return-taint heuristic must not mark a function's
// return tainted on a bare `return "const"` / `return nil` just because a
// source param coexists. It must still taint returns that lexically reference
// param-derived data (directly, or through a local assignment).
//
// These tests drive the regex fallback in computeTaintSigInner by passing nil
// flows; the param `r *http.Request` is recognised as a SrcUserInput source
// param, and no sink call is present, so control reaches the return block.

func TestComputeTaintSig_CH5_ConstReturn_NotTainted(t *testing.T) {
	content := `func pick(r *http.Request) string {
	return "constant"
}`
	node := &FuncNode{
		Name:      "pick",
		FilePath:  "/app/pick.go",
		StartLine: 1,
		EndLine:   3,
		Language:  rules.LangGo,
	}
	sig := ComputeTaintSig(node, content, rules.LangGo, nil, nil)
	if len(sig.SourceParams) == 0 {
		t.Fatalf("precondition: expected *http.Request to be a source param, got none")
	}
	if len(sig.SinkCalls) != 0 {
		t.Fatalf("precondition: expected no sink calls, got %d", len(sig.SinkCalls))
	}
	if len(sig.TaintedReturns) != 0 {
		t.Errorf("CH5: `return \"constant\"` must NOT taint the return; got TaintedReturns=%v", sig.TaintedReturns)
	}
}

func TestComputeTaintSig_CH5_NilReturn_NotTainted(t *testing.T) {
	content := `func pick(r *http.Request) error {
	return nil
}`
	node := &FuncNode{
		Name:      "pick",
		FilePath:  "/app/pick.go",
		StartLine: 1,
		EndLine:   3,
		Language:  rules.LangGo,
	}
	sig := ComputeTaintSig(node, content, rules.LangGo, nil, nil)
	if len(sig.TaintedReturns) != 0 {
		t.Errorf("CH5: `return nil` must NOT taint the return; got TaintedReturns=%v", sig.TaintedReturns)
	}
}

func TestComputeTaintSig_CH5_DirectParamReturn_StillTainted(t *testing.T) {
	content := `func pick(r *http.Request) string {
	return r.URL.Path
}`
	node := &FuncNode{
		Name:      "pick",
		FilePath:  "/app/pick.go",
		StartLine: 1,
		EndLine:   3,
		Language:  rules.LangGo,
	}
	sig := ComputeTaintSig(node, content, rules.LangGo, nil, nil)
	if len(sig.SourceParams) == 0 {
		t.Fatalf("precondition: expected *http.Request to be a source param, got none")
	}
	if len(sig.TaintedReturns) == 0 {
		t.Errorf("CH5 recall: `return r.URL.Path` references the param and MUST taint the return; got none")
	}
}

func TestComputeTaintSig_CH5_IndirectParamReturn_StillTainted(t *testing.T) {
	// tmp is assigned from a param-derived expression, then returned. The
	// return expression mentions `tmp`, not `r`, so direct token matching
	// alone would miss it — the local-derivation pass must catch it.
	content := `func pick(r *http.Request) string {
	tmp := r.URL.Path
	return tmp
}`
	node := &FuncNode{
		Name:      "pick",
		FilePath:  "/app/pick.go",
		StartLine: 1,
		EndLine:   4,
		Language:  rules.LangGo,
	}
	sig := ComputeTaintSig(node, content, rules.LangGo, nil, nil)
	if len(sig.TaintedReturns) == 0 {
		t.Errorf("CH5 recall: `tmp := r.URL.Path; return tmp` MUST taint the return; got none")
	}
}

// Unit coverage for the splitAssignment / LHS-name helpers driving the
// indirect-derivation pass, across the assignment forms seen in the regex
// fallback's polyglot input.
func TestSplitAssignment_Forms(t *testing.T) {
	cases := []struct {
		line    string
		wantLHS []string
		wantRHS string
		wantOK  bool
	}{
		{"tmp := r.URL.Path", []string{"tmp"}, "r.URL.Path", true},
		{"  x = foo(p)  ", []string{"x"}, "foo(p)", true},
		{"var s = clean(req)", []string{"s"}, "clean(req)", true},
		{"const c = literal", []string{"c"}, "literal", true},
		{"let v = q.value", []string{"v"}, "q.value", true},
		{"$out = $in . suffix", []string{"out"}, "$in . suffix", true},
		{"a, b := split(p)", []string{"a", "b"}, "split(p)", true},
		{"buf += p", []string{"buf"}, "p", true},
		// Non-assignments / comparisons must NOT parse as assignments.
		{"return x", nil, "", false},
		{"if a == b {", nil, "", false},
		{"if a != b {", nil, "", false},
		{"if a >= b {", nil, "", false},
	}
	for _, tc := range cases {
		lhs, rhs, ok := splitAssignment(tc.line)
		if ok != tc.wantOK {
			t.Errorf("splitAssignment(%q): ok=%v, want %v", tc.line, ok, tc.wantOK)
			continue
		}
		if !ok {
			continue
		}
		if rhs != tc.wantRHS {
			t.Errorf("splitAssignment(%q): rhs=%q, want %q", tc.line, rhs, tc.wantRHS)
		}
		if len(lhs) != len(tc.wantLHS) {
			t.Errorf("splitAssignment(%q): lhs=%v, want %v", tc.line, lhs, tc.wantLHS)
			continue
		}
		for i := range lhs {
			if lhs[i] != tc.wantLHS[i] {
				t.Errorf("splitAssignment(%q): lhs[%d]=%q, want %q", tc.line, i, lhs[i], tc.wantLHS[i])
			}
		}
	}
}

// TestCH5_CrossFile_ConstReturnHelper_NoSpuriousFinding is the end-to-end
// integration demonstration of CH5: it drives the same path the real
// `batou scan` cross-file lane uses.
//
// astflow produces ZERO flows for a `func helper(r *http.Request) string {
// return "const" }` (it tracks source->sink, not source->return; verified
// empirically), so the callee's signature is computed by the regex fallback
// in computeTaintSigInner — exactly the code CH5 tightens. The caller stores
// the helper's return and forwards it to a SQL sink.
//
// WITHOUT the fix the callee's TaintedReturns is populated on the mere
// coexistence of a source param and a `return`, the cross-file walker's
// fast-skip at crossfile_walk.go:121 is bypassed, and a spurious CWE-89
// cross-file finding is emitted. WITH the fix the constant return leaves
// TaintedReturns empty, the callee is correctly fast-skipped, and no finding
// is produced.
func TestCH5_CrossFile_ConstReturnHelper_NoSpuriousFinding(t *testing.T) {
	findings := runCH5GoCrossFile(t, `package app

import "net/http"

func pickTable(r *http.Request) string {
	_ = r
	return "users"
}
`)
	for _, f := range findings {
		if f.CWEID == "CWE-89" {
			t.Fatalf("CH5: constant-return helper must NOT drive a cross-file CWE-89 finding; got %+v", f)
		}
	}
}

// TestCH5_CrossFile_ParamReturnHelper_StillFinds is the recall counterpart:
// when the helper actually returns param-derived data, the cross-file flow
// must still surface (the fix must not over-suppress).
func TestCH5_CrossFile_ParamReturnHelper_StillFinds(t *testing.T) {
	findings := runCH5GoCrossFile(t, `package app

import "net/http"

func pickTable(r *http.Request) string {
	name := r.URL.Query().Get("t")
	return name
}
`)
	found := false
	for _, f := range findings {
		if f.CWEID == "CWE-89" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("CH5 recall: param-derived return MUST still drive a cross-file CWE-89 finding; got %d findings: %+v", len(findings), findings)
	}
}

// runCH5GoCrossFile builds a two-file Go package where caller.go forwards the
// return of pickTable (defined in helperSrc) into a SQL sink, computes BOTH
// signatures via ComputeTaintSig with nil flows (the regex-fallback path the
// real pipeline uses for flow-less helpers), resolves cross-file edges, and
// returns the cross-file walk findings.
func runCH5GoCrossFile(t *testing.T, helperSrc string) []rules.Finding {
	t.Helper()
	root := t.TempDir()
	cg := NewCallGraph(root, "test")

	callerPath := filepath.Join(root, "caller.go")
	helperPath := filepath.Join(root, "helper.go")

	callerSrc := `package app

import (
	"database/sql"
	"net/http"
)

func Handle(w http.ResponseWriter, r *http.Request) {
	tbl := pickTable(r)
	db.Exec("SELECT * FROM " + tbl)
}

var db *sql.DB
`

	callerNode := &FuncNode{
		ID:        callerPath + ":Handle",
		FilePath:  callerPath,
		Name:      "Handle",
		Package:   "app",
		Language:  rules.LangGo,
		StartLine: 8,
		EndLine:   11,
		RawCalls:  []string{"pickTable"},
	}
	callerNode.TaintSig = ComputeTaintSig(callerNode, callerSrc, rules.LangGo, nil, nil)
	cg.AddNode(callerNode)

	helperNode := &FuncNode{
		ID:        helperPath + ":pickTable",
		FilePath:  helperPath,
		Name:      "pickTable",
		Package:   "app",
		Language:  rules.LangGo,
		StartLine: 5,
		EndLine:   8,
	}
	helperNode.TaintSig = ComputeTaintSig(helperNode, helperSrc, rules.LangGo, nil, nil)
	cg.AddNode(helperNode)

	cg.ModulePaths = map[rules.Language]string{rules.LangGo: "example.com/proj"}
	cg.ModuleRoots = map[rules.Language]string{rules.LangGo: root}

	contents := map[string][]byte{
		callerPath: []byte(callerSrc),
		helperPath: []byte(helperSrc),
	}
	ResolveCrossFileEdges(cg, root, contents)

	strContents := map[string]string{
		callerPath: callerSrc,
		helperPath: helperSrc,
	}
	return WalkCrossFileTaintFlows(cg, strContents)
}
