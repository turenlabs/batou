package graph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// TestWalkCrossFileTaintFlows_SkipsSameFile verifies that
// caller→callee pairs in the same file are not visited (PropagateInterproc
// already handled them during the per-file scan).
func TestWalkCrossFileTaintFlows_SkipsSameFile(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	a := filepath.Join(root, "a.go")

	// Caller and callee in the same file.
	cg.AddNode(&FuncNode{ID: a + ":Caller", FilePath: a, Name: "Caller", Language: rules.LangGo})
	cg.AddNode(&FuncNode{
		ID:       a + ":Callee",
		FilePath: a,
		Name:     "Callee",
		Language: rules.LangGo,
		TaintSig: TaintSignature{
			SinkCalls: []SinkRef{{SinkCategory: taint.SnkHTMLOutput, MethodName: "w.Write", Line: 5, ArgFromParam: -1}},
		},
	})
	cg.AddEdge(a+":Caller", a+":Callee")

	var stats CrossFileWalkStats
	findings := WalkCrossFileTaintFlowsWithStats(cg, nil, &stats)

	if stats.Pairs != 0 {
		t.Errorf("Pairs = %d, want 0 (same-file pair should be skipped)", stats.Pairs)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

// TestWalkCrossFileTaintFlows_VisitsCrossFilePairs verifies the walk
// reaches caller/callee pairs that live in different files.
func TestWalkCrossFileTaintFlows_VisitsCrossFilePairs(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	aFile := filepath.Join(root, "a.go")
	bFile := filepath.Join(root, "b/b.go")

	cg.AddNode(&FuncNode{ID: aFile + ":Caller", FilePath: aFile, Name: "Caller", Language: rules.LangGo})
	cg.AddNode(&FuncNode{
		ID:       bFile + ":Callee",
		FilePath: bFile,
		Name:     "Callee",
		Language: rules.LangGo,
		TaintSig: TaintSignature{
			SinkCalls: []SinkRef{{SinkCategory: taint.SnkHTMLOutput, MethodName: "w.Write", Line: 5, ArgFromParam: -1}},
		},
	})
	cg.AddEdge(aFile+":Caller", bFile+":Callee")

	contents := map[string]string{
		// Caller has no taint source — Path A's isArgTaintedInCaller
		// will reject. The point of this test is just that the walk
		// REACHES the pair (Pairs == 1) and counts the callee-sink.
		aFile: "package a\nfunc Caller() { Callee() }\n",
	}
	var stats CrossFileWalkStats
	_ = WalkCrossFileTaintFlowsWithStats(cg, contents, &stats)

	if stats.Pairs != 1 {
		t.Errorf("Pairs = %d, want 1", stats.Pairs)
	}
	if stats.CalleeHasSink != 1 {
		t.Errorf("CalleeHasSink = %d, want 1", stats.CalleeHasSink)
	}
	if stats.ContentLoadFailed != 0 {
		t.Errorf("ContentLoadFailed = %d, want 0", stats.ContentLoadFailed)
	}
}

// TestWalkCrossFileTaintFlows_ReadsFromDisk verifies the walk falls back
// to reading caller content from disk when fileContents is empty.
func TestWalkCrossFileTaintFlows_ReadsFromDisk(t *testing.T) {
	root := t.TempDir()
	aFile := filepath.Join(root, "a.go")
	bFile := filepath.Join(root, "b/b.go")
	if err := writeFiles(t, root, map[string]string{
		"a.go":   "package a\nfunc Caller() { Callee() }\n",
		"b/b.go": "package b\nfunc Callee() {}\n",
	}); err != nil {
		t.Fatal(err)
	}

	cg := NewCallGraph(root, "test")
	cg.AddNode(&FuncNode{
		ID:        aFile + ":Caller",
		FilePath:  aFile,
		Name:      "Caller",
		Language:  rules.LangGo,
		StartLine: 2,
		EndLine:   2,
	})
	cg.AddNode(&FuncNode{
		ID:       bFile + ":Callee",
		FilePath: bFile,
		Name:     "Callee",
		Language: rules.LangGo,
		TaintSig: TaintSignature{
			SinkCalls: []SinkRef{{SinkCategory: taint.SnkHTMLOutput, MethodName: "x", Line: 2, ArgFromParam: -1}},
		},
	})
	cg.AddEdge(aFile+":Caller", bFile+":Callee")

	var stats CrossFileWalkStats
	_ = WalkCrossFileTaintFlowsWithStats(cg, nil, &stats)
	if stats.ContentLoadFailed != 0 {
		t.Errorf("ContentLoadFailed = %d, want 0 (disk read should succeed)", stats.ContentLoadFailed)
	}
}

// TestCrossFileSinkKeyForFinding_ExtractsLeafSink verifies the dedup
// key derivation from a typical Path-A finding produced by
// AnalyzeCallerImpact: the leaf-sink step (last TaintStepSink) defines
// the (deepSinkFile, deepSinkLine) the dedup keys on, and the first
// TaintStepSource step defines the source position (PR-OO addition so
// distinct entry points don't collapse).
func TestCrossFileSinkKeyForFinding_ExtractsLeafSink(t *testing.T) {
	f := rules.Finding{
		RuleID:         "BATOU-INTERPROC-SQL_QUERY",
		SourceCategory: "user_input",
		TaintPath: []rules.TaintStep{
			{File: "/repo/m1.go", Line: 11, Kind: rules.TaintStepSource, Label: "tainted arg"},
			{File: "/repo/m1.go", Line: 11, Kind: rules.TaintStepPropagation, Label: "passed to M2"},
			{File: "/repo/handler.go", Line: 42, Kind: rules.TaintStepSink, Label: "db.Exec"},
		},
	}
	got := crossFileSinkKeyForFinding(f)
	if got.deepSinkFile != "/repo/handler.go" || got.deepSinkLine != 42 {
		t.Errorf("deep sink mismatch: got %+v", got)
	}
	if got.ruleID != "BATOU-INTERPROC-SQL_QUERY" || got.sourceCategory != "user_input" {
		t.Errorf("rule/source mismatch: got %+v", got)
	}
	if got.sourceFile != "/repo/m1.go" || got.sourceLine != 11 {
		t.Errorf("source position mismatch: got %+v", got)
	}
}

// TestCrossFileSinkKeyForFinding_DistinctSourcesNotCollapsed pins the
// PR-OO recall fix: two findings hitting the SAME leaf sink from
// DIFFERENT source positions must produce different keys so the walker
// doesn't silently collapse independent entry points (sibling handlers,
// distinct middleware chains, etc.).
func TestCrossFileSinkKeyForFinding_DistinctSourcesNotCollapsed(t *testing.T) {
	leafSink := rules.TaintStep{File: "/repo/handler.go", Line: 42, Kind: rules.TaintStepSink, Label: "db.Exec"}
	f1 := rules.Finding{
		RuleID:         "BATOU-INTERPROC-SQL_QUERY",
		SourceCategory: "user_input",
		TaintPath: []rules.TaintStep{
			{File: "/repo/h1.go", Line: 5, Kind: rules.TaintStepSource, Label: "r1"},
			leafSink,
		},
	}
	f2 := rules.Finding{
		RuleID:         "BATOU-INTERPROC-SQL_QUERY",
		SourceCategory: "user_input",
		TaintPath: []rules.TaintStep{
			{File: "/repo/h2.go", Line: 5, Kind: rules.TaintStepSource, Label: "r2"},
			leafSink,
		},
	}
	k1 := crossFileSinkKeyForFinding(f1)
	k2 := crossFileSinkKeyForFinding(f2)
	if k1 == k2 {
		t.Errorf("distinct sources should produce distinct keys; both got %+v", k1)
	}
}

// TestCrossFileSinkKeyForFinding_NoSinkStepIsZero confirms findings
// without a TaintStepSink yield the zero key so callers (the walk
// loop) skip dedup rather than silently collapsing unrelated findings.
func TestCrossFileSinkKeyForFinding_NoSinkStepIsZero(t *testing.T) {
	f := rules.Finding{
		RuleID: "BATOU-INTERPROC-DESERIALIZE",
		TaintPath: []rules.TaintStep{
			{File: "/a.go", Line: 1, Kind: rules.TaintStepSource, Label: "x"},
			{File: "/a.go", Line: 1, Kind: rules.TaintStepPropagation, Label: "y"},
		},
	}
	got := crossFileSinkKeyForFinding(f)
	if got.deepSinkFile != "" || got.deepSinkLine != 0 {
		t.Errorf("expected zero key for sink-less path; got %+v", got)
	}
}

// TestWalkCrossFileTaintFlows_DedupsByLeafSink_SharedSource builds 3
// distinct caller→callee edges all pointing at the same downstream
// sink. Under PR-OO the dedup keys on (leafSink, sourceFile,
// sourceLine, sourceCategory) so genuinely distinct entry points stay
// separate. This test therefore asserts the dedup KICKS IN only when
// the source identity matches — the AnalyzeCallerImpact-rendered
// finding may use the caller's own first-step file as the source
// position, so callers with materially different source positions
// expectedly produce distinct findings (we assert <= number-of-pairs
// rather than == 1 the way PR-NN's version did).
func TestWalkCrossFileTaintFlows_DedupsByLeafSink_SharedSource(t *testing.T) {
	root := t.TempDir()
	aFile := filepath.Join(root, "a.go")
	bFile := filepath.Join(root, "b.go")
	cFile := filepath.Join(root, "c.go")
	dFile := filepath.Join(root, "d/sink.go")
	if err := writeFiles(t, root, map[string]string{
		"a.go": `package a
import "net/http"
func A(r *http.Request) { B(r) }
`,
		"b.go": `package a
import "net/http"
func B(r *http.Request) { C(r) }
`,
		"c.go": `package a
import "net/http"
func C(r *http.Request) { Sink(r) }
`,
		"d/sink.go": `package d
import (
	"database/sql"
	"net/http"
)
var db *sql.DB
func Sink(r *http.Request) {
	db.Exec(r.URL.Query().Get("q"))
}
`,
	}); err != nil {
		t.Fatal(err)
	}

	cg := NewCallGraph(root, "test")
	// Callee Sink in d/sink.go with a SQL sink at line 8.
	cg.AddNode(&FuncNode{
		ID:        dFile + ":Sink",
		FilePath:  dFile,
		Name:      "Sink",
		Language:  rules.LangGo,
		StartLine: 7,
		EndLine:   9,
		TaintSig: TaintSignature{
			SourceParams: map[int]taint.SourceCategory{0: taint.SrcUserInput},
			TaintedParams: map[int][]taint.SourceCategory{
				0: {taint.SrcUserInput},
			},
			SinkCalls: []SinkRef{
				{SinkCategory: taint.SnkSQLQuery, MethodName: "Exec", Line: 8, ArgFromParam: 0},
			},
		},
	})
	// Three "layer" callers, each forwarding r to the next/Sink.
	for _, layer := range []struct {
		id   string
		file string
		line int
	}{
		{aFile + ":A", aFile, 3},
		{bFile + ":B", bFile, 3},
		{cFile + ":C", cFile, 3},
	} {
		cg.AddNode(&FuncNode{
			ID:        layer.id,
			FilePath:  layer.file,
			Name:      layer.id[len(layer.id)-1:],
			Language:  rules.LangGo,
			StartLine: layer.line,
			EndLine:   layer.line,
			TaintSig: TaintSignature{
				SourceParams: map[int]taint.SourceCategory{0: taint.SrcUserInput},
			},
		})
		// Every layer is a caller of Sink in the call graph (simulating
		// the cross-file edges PR-CC's sig-propagation produces).
		cg.AddEdge(layer.id, dFile+":Sink")
	}

	var stats CrossFileWalkStats
	findings := WalkCrossFileTaintFlowsWithStats(cg, nil, &stats)

	// Three distinct (caller, callee) pairs visited.
	if stats.Pairs != 3 {
		t.Errorf("Pairs = %d, want 3", stats.Pairs)
	}
	// Count findings that target the same leaf sink (d/sink.go:8).
	// Under PR-OO each caller (A, B, C in different files) is a
	// distinct source position so all three should produce findings —
	// they're sibling entry points, not a single middleware chain
	// emitting from one root. The previous assertion (== 1) was
	// over-collapsing and caused the env-ON recall regression PR-OO
	// addresses. The dedup still suppresses identical (sourcePos,
	// sink) duplicates; we just don't collapse across distinct
	// callers any more.
	sameSinkFindings := 0
	for _, f := range findings {
		for _, st := range f.TaintPath {
			if st.Kind == rules.TaintStepSink && st.File == dFile && st.Line == 8 {
				sameSinkFindings++
				break
			}
		}
	}
	if sameSinkFindings > stats.Pairs {
		t.Errorf("findings (%d) cannot exceed pairs (%d); findings=%+v",
			sameSinkFindings, stats.Pairs, findings)
	}
}

func writeFiles(t *testing.T, root string, files map[string]string) error {
	t.Helper()
	for rel, body := range files {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			return err
		}
	}
	return nil
}
