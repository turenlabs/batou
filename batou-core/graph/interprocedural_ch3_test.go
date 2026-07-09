package graph

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// TestAnalyzeCallerImpact_PerFieldReturn_CleanFieldNotTainted is the CH3
// load-bearing test. A callee returns a struct with ONE tainted field
// (Name) and one clean field (Page), recorded as the per-field tainted
// return path "0.Name" (TaintedReturnPaths). It asserts the consumer-side
// field gate in checkCallerUsesTaintedReturn:
//
//   - a caller that reads the CLEAN field (res.Page) into a SQL sink must
//     NOT be flagged — the false positive the per-field map removes, AND
//   - a caller that reads the TAINTED field (res.Name) into the same sink
//     MUST still be flagged — recall is preserved.
//
// Load-bearing proof: with the whole-return path (the old behaviour, which
// you get by stashing crossfile_walk_golang_field.go + interprocedural.go),
// either the callee carries no Path-B driver at all (so BOTH callers go
// unflagged and the recall half fails) or, were the field gate absent, the
// clean-field caller WOULD be flagged and the FP half fails. The test
// pins both halves so the field-sensitivity is what makes it pass.
func TestAnalyzeCallerImpact_PerFieldReturn_CleanFieldNotTainted(t *testing.T) {
	newCallee := func() *FuncNode {
		return &FuncNode{
			ID:        "pkg.build",
			Name:      "build",
			FilePath:  "/app/source.go",
			StartLine: 10,
			EndLine:   13,
			Language:  rules.LangGo,
			TaintSig: TaintSignature{
				// Per-field: only the Name field of the returned struct is
				// tainted; Page is a literal and carries NO taint path. Note
				// TaintedReturns (whole-return) is intentionally EMPTY — this
				// is exactly the partial-struct shape CH3 targets.
				TaintedReturnPaths: map[string][]taint.SourceCategory{
					"0.Name": {taint.SrcUserInput},
				},
			},
		}
	}

	run := func(t *testing.T, callerContent string) []rules.Finding {
		t.Helper()
		cg := NewCallGraph("/project", "test")
		callee := newCallee()
		caller := &FuncNode{
			ID:        "pkg.handler",
			Name:      "handler",
			FilePath:  "/app/handler.go",
			StartLine: 1,
			EndLine:   5,
			Language:  rules.LangGo,
		}
		cg.AddNode(callee)
		cg.AddNode(caller)
		cg.AddEdge(caller.ID, callee.ID)
		return AnalyzeCallerImpact(cg, caller, callee, callerContent)
	}

	// CLEAN-field read: res.Page is the literal field — must NOT be flagged.
	cleanCaller := `func handler() {
	res := build(r)
	db.Query("SELECT * FROM t WHERE p='" + res.Page + "'")
}`
	if f := run(t, cleanCaller); len(f) != 0 {
		t.Fatalf("clean-field read should NOT be flagged (per-field FP), got %d findings: %+v", len(f), f)
	}

	// TAINTED-field read: res.Name carries user input — MUST be flagged.
	taintedCaller := `func handler() {
	res := build(r)
	db.Query("SELECT * FROM t WHERE n='" + res.Name + "'")
}`
	f := run(t, taintedCaller)
	if len(f) == 0 {
		t.Fatalf("tainted-field read MUST be flagged (recall preserved), got 0 findings")
	}
	var sqlFinding *rules.Finding
	for i := range f {
		if f[i].SinkCategory == string(taint.SnkSQLQuery) {
			sqlFinding = &f[i]
			break
		}
	}
	if sqlFinding == nil {
		t.Fatalf("expected a SQL-query interprocedural finding for the tainted field read, got %+v", f)
	}
	if sqlFinding.SourceCategory != string(taint.SrcUserInput) {
		t.Errorf("source category = %q, want %q (carried from the tainted return PATH)",
			sqlFinding.SourceCategory, taint.SrcUserInput)
	}
}

// TestScanGoBodyForTaintedReturnPaths covers the CH3 PRODUCER: a Go callee
// body that returns a composite literal with a mix of tainted and clean
// fields must yield TaintedReturnPaths keyed only on the tainted fields.
func TestScanGoBodyForTaintedReturnPaths(t *testing.T) {
	body := `func build(r *http.Request) Result {
	return Result{Name: r.FormValue("n"), Page: "static.html"}
}`
	paths := scanGoBodyForTaintedReturnPaths(body)
	if paths == nil {
		t.Fatal("expected non-nil TaintedReturnPaths for a partial-struct return")
	}
	if _, ok := paths["0.Name"]; !ok {
		t.Errorf("expected tainted return path %q, got %v", "0.Name", paths)
	}
	if _, ok := paths["0.Page"]; ok {
		t.Errorf("clean field Page must NOT appear as a tainted return path; got %v", paths)
	}

	// Field-built return: `v.Name = src; return v`.
	body2 := `func build(r *http.Request) Result {
	var v Result
	v.Name = r.FormValue("n")
	v.Page = "static.html"
	return v
}`
	paths2 := scanGoBodyForTaintedReturnPaths(body2)
	if _, ok := paths2["0.Name"]; !ok {
		t.Errorf("field-built: expected tainted return path %q, got %v", "0.Name", paths2)
	}
	if _, ok := paths2["0.Page"]; ok {
		t.Errorf("field-built: clean field Page must NOT be tainted; got %v", paths2)
	}

	// All-clean return: no tainted paths → nil (falls back to whole-return).
	body3 := `func build() Result {
	return Result{Name: "x", Page: "y"}
}`
	if p := scanGoBodyForTaintedReturnPaths(body3); p != nil {
		t.Errorf("all-clean return should yield nil paths, got %v", p)
	}
}
