package graph

// Load-bearing test for the write-time hook two-hop cross-file lane.
//
// Scenario (the gap two-hop closes): the EDITED file A calls B (file B),
// B is a PURE FORWARDER that passes its param to C's sink (file C), and
// B's persisted signature does NOT carry C's lifted sink (the state when
// the scan's whole-graph fixpoint hasn't propagated the lift into B, or
// B was edited after the last scan). The one-hop walk skips A->B because
// B has no usable sink signature. LiftSecondHopSinksForFile lifts C's
// sink into B in-memory, after which the one-hop walk surfaces the full
// A->B->C flow.
//
// The test asserts BOTH directions of the with/without contract:
//   - WITHOUT the second-hop lift: the one-hop walk emits nothing.
//   - WITH the second-hop lift: the one-hop walk emits the A->B->C flow,
//     and the rendered taint path reaches C's sink file/line.

import (
	"path/filepath"
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// buildTwoHopChain constructs the A->B->C Go graph used by the two-hop
// tests. A (edited file) -> B (forwarder, NO sink sig) -> C (SQL sink).
// Returns the graph plus the three file paths and the in-memory content
// map carrying the edited file's source.
func buildTwoHopChain(t *testing.T) (cg *CallGraph, aFile, bFile, cFile string, contents map[string]string) {
	t.Helper()
	root := t.TempDir()
	aFile = filepath.Join(root, "handler", "a.go")
	bFile = filepath.Join(root, "service", "b.go")
	cFile = filepath.Join(root, "storage", "c.go")

	// B forwards its param to C; C sinks it. Written to disk so the
	// second-hop lift (which reads B from disk via loadCallerFile) and the
	// one-hop walk can extract their bodies.
	writeFixture(t, root, map[string]string{
		"service/b.go": `package service

import "example.com/app/storage"

func Forward(q string) {
	storage.RunQuery(q)
}
`,
		"storage/c.go": `package storage

import "database/sql"

var db *sql.DB

func RunQuery(query string) {
	db.Exec(query)
}
`,
	})

	cg = NewCallGraph(root, "")
	cg.PackageIndex = NewPackageIndex() // scan-built marker

	// A: the edited handler. Passes a user-input param to B.
	cg.AddNode(&FuncNode{
		ID: aFile + ":Handler", FilePath: aFile, Name: "Handler",
		Language: rules.LangGo, StartLine: 3, EndLine: 5,
		TaintSig: TaintSignature{SourceParams: map[int]taint.SourceCategory{1: taint.SrcUserInput}},
	})
	// B: pure forwarder. CRITICAL: NO sink/return signature persisted —
	// this is the state the two-hop lift must repair. B forwards param 0
	// to C's sink param 0.
	cg.AddNode(&FuncNode{
		ID: bFile + ":Forward", FilePath: bFile, Name: "Forward",
		Language: rules.LangGo, StartLine: 5, EndLine: 7,
	})
	// C: the leaf SQL sink, fed by param 0.
	cg.AddNode(&FuncNode{
		ID: cFile + ":RunQuery", FilePath: cFile, Name: "RunQuery",
		Language: rules.LangGo, StartLine: 7, EndLine: 9,
		TaintSig: TaintSignature{
			SinkCalls: []SinkRef{{SinkCategory: taint.SnkSQLQuery, MethodName: "db.Exec", Line: 8, ArgFromParam: 0}},
		},
	})

	cg.AddEdge(aFile+":Handler", bFile+":Forward")  // A -> B
	cg.AddEdge(bFile+":Forward", cFile+":RunQuery") // B -> C

	contents = map[string]string{
		aFile: "package handler\nimport \"net/http\"\nfunc Handler(w http.ResponseWriter, r *http.Request) {\n\tservice.Forward(r.URL.Query().Get(\"q\"))\n}\n",
	}
	return cg, aFile, bFile, cFile, contents
}

// TestTwoHop_LiftConnectsChain_OneHopMisses is the load-bearing test.
// It pins the with/without contract: the one-hop walk alone misses the
// A->B->C flow (B has no sink sig); the two-hop lift makes the same walk
// surface it.
func TestTwoHop_LiftConnectsChain_OneHopMisses(t *testing.T) {
	// --- WITHOUT the second hop: one-hop walk emits nothing. ---
	cg, aFile, _, _, contents := buildTwoHopChain(t)
	oneHop := WalkCrossFileTaintFlowsForCaller(cg, aFile, contents)
	if len(oneHop) != 0 {
		t.Fatalf("precondition failed: one-hop walk should miss the A->B->C flow "+
			"(B carries no sink signature), but got %d findings: %+v", len(oneHop), oneHop)
	}

	// --- WITH the second hop: lift C's sink into B, re-walk. ---
	// Fresh graph so the first walk's lazy populations don't leak in.
	cg, aFile, bFile, cFile, contents := buildTwoHopChain(t)
	stats := LiftSecondHopSinksForFile(cg, aFile, contents)
	if stats.Intermediates == 0 {
		t.Fatalf("second-hop lift processed no intermediates; expected B to be re-lifted")
	}
	if stats.SinksLifted == 0 {
		t.Fatalf("second-hop lift added no sinks; expected C's sink lifted into B")
	}
	// B must now carry a usable (inherited) sink.
	b := cg.GetNode(bFile + ":Forward")
	if !calleeHasUsableSignature(b) {
		t.Fatalf("B should carry a lifted sink after the second-hop lift; sig=%+v", b.TaintSig)
	}

	twoHop := WalkCrossFileTaintFlowsForCaller(cg, aFile, contents)
	if len(twoHop) == 0 {
		t.Fatalf("two-hop walk should surface the A->B->C flow, got 0 findings")
	}
	// The rendered path must reach C's leaf sink (lifted SinkRef carries
	// OriginFile/OriginLine pointing at C).
	sawCSink := false
	for _, f := range twoHop {
		for _, st := range f.TaintPath {
			if st.Kind == rules.TaintStepSink && st.File == cFile {
				sawCSink = true
			}
		}
	}
	if !sawCSink {
		t.Errorf("two-hop finding's taint path should reach C's sink file %q; findings=%+v", cFile, twoHop)
	}
}

// TestTwoHop_NoOpWhenIntermediateAlreadyHasSink confirms the lift does
// NOT redundantly re-process a B that already carries a usable signature
// (the one-hop walk already covers it), keeping the second hop cheap.
func TestTwoHop_NoOpWhenIntermediateAlreadyHasSink(t *testing.T) {
	cg, aFile, bFile, _, contents := buildTwoHopChain(t)
	// Give B a direct sink so calleeHasUsableSignature(B) is already true.
	b := cg.GetNode(bFile + ":Forward")
	b.TaintSig.SinkCalls = []SinkRef{{SinkCategory: taint.SnkSQLQuery, MethodName: "db.Exec", Line: 6, ArgFromParam: 0}}

	stats := LiftSecondHopSinksForFile(cg, aFile, contents)
	if stats.Intermediates != 0 {
		t.Errorf("B already has a usable sink; lift should skip it, got Intermediates=%d", stats.Intermediates)
	}
}

// TestTwoHop_NoOpWhenIntermediateIsLeaf confirms a B with no outbound
// cross-file callee (a true leaf the one-hop walk already covers) is not
// processed by the second-hop lift.
func TestTwoHop_NoOpWhenIntermediateIsLeaf(t *testing.T) {
	root := t.TempDir()
	aFile := filepath.Join(root, "a.go")
	bFile := filepath.Join(root, "b.go")
	cg := NewCallGraph(root, "")
	cg.PackageIndex = NewPackageIndex()
	cg.AddNode(&FuncNode{ID: aFile + ":A", FilePath: aFile, Name: "A", Language: rules.LangGo, StartLine: 1, EndLine: 2})
	// B has no outbound calls at all -> not a forwarder.
	cg.AddNode(&FuncNode{ID: bFile + ":B", FilePath: bFile, Name: "B", Language: rules.LangGo, StartLine: 1, EndLine: 2})
	cg.AddEdge(aFile+":A", bFile+":B")

	stats := LiftSecondHopSinksForFile(cg, aFile, map[string]string{aFile: "package a\nfunc A(){ B() }\n"})
	if stats.Intermediates != 0 {
		t.Errorf("leaf B (no cross-file callee) should be skipped, got Intermediates=%d", stats.Intermediates)
	}
}

// TestTwoHop_Bounded confirms the second-hop intermediate count is capped
// at maxSecondHopCallees.
func TestTwoHop_Bounded(t *testing.T) {
	root := t.TempDir()
	aFile := filepath.Join(root, "a.go")
	cg := NewCallGraph(root, "")
	cg.PackageIndex = NewPackageIndex()
	cg.AddNode(&FuncNode{ID: aFile + ":A", FilePath: aFile, Name: "A", Language: rules.LangGo, StartLine: 1, EndLine: 2})

	// Wire A to (cap+10) distinct cross-file forwarders, each of which
	// calls a further cross-file node (so they pass the leaf guard) but
	// has no usable sig (so they'd be candidates for the lift).
	total := maxSecondHopCallees + 10
	for i := 0; i < total; i++ {
		bFile := filepath.Join(root, "b", "b"+twoHopItoa(i)+".go")
		cFile := filepath.Join(root, "c", "c"+twoHopItoa(i)+".go")
		bID := bFile + ":B"
		cID := cFile + ":C"
		cg.AddNode(&FuncNode{ID: bID, FilePath: bFile, Name: "B", Language: rules.LangGo, StartLine: 1, EndLine: 2})
		cg.AddNode(&FuncNode{ID: cID, FilePath: cFile, Name: "C", Language: rules.LangGo, StartLine: 1, EndLine: 2})
		cg.AddEdge(aFile+":A", bID)
		cg.AddEdge(bID, cID)
	}

	stats := LiftSecondHopSinksForFile(cg, aFile, map[string]string{aFile: "package a"})
	if stats.Intermediates > maxSecondHopCallees {
		t.Errorf("second-hop intermediates = %d, must be capped at %d", stats.Intermediates, maxSecondHopCallees)
	}
	if !stats.Capped {
		t.Errorf("expected Capped=true with %d candidate intermediates (cap %d)", total, maxSecondHopCallees)
	}
}

// twoHopItoa is a tiny dependency-free int->string for the bound test.
func twoHopItoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
