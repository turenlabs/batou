package graph

// Latency benchmark for the write-time hook two-hop lane.
//
// Measures the added cost of LiftSecondHopSinksForFile on an
// aggregator-shaped graph: one edited file whose functions call into
// many distinct cross-file forwarder (B) nodes, each of which forwards
// to a leaf sink (C) in yet another file. This is the worst case the
// two-hop lift pays for — every B is a pure forwarder with no persisted
// sink, so every B triggers a lift pass that reads B's file and
// regex-scans its body.
//
// Run:
//   go test -run x -bench 'BenchmarkHookTwoHop' -benchmem ./graph/
//
// The benchmark reports the WALL of the second-hop lift + the one-hop
// walk that consumes it (the full added hook work), vs the one-hop walk
// alone, so the multiplier is the real write-time delta.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// buildAggregatorGraph builds a graph shaped like a busy hub file: the
// edited file A has `fanout` distinct cross-file callees (B_i in their
// own files), each forwarding its param to a leaf SQL sink C_i in a
// third file. Returns the graph, the edited file path, and the
// in-memory content map for A. B/C files are written to disk so the lift
// and walk can read their bodies.
func buildAggregatorGraph(b *testing.B, fanout int) (*CallGraph, string, map[string]string) {
	b.Helper()
	root := b.TempDir()
	aFile := filepath.Join(root, "hub.go")

	cg := NewCallGraph(root, "")
	cg.PackageIndex = NewPackageIndex()

	// A single aggregator function in the edited file that calls every B.
	// Body has one call per line so each forwarder is reachable.
	var aBody string
	aBody = "package hub\n\nfunc Hub(q string) {\n"
	cg.AddNode(&FuncNode{
		ID: aFile + ":Hub", FilePath: aFile, Name: "Hub",
		Language: rules.LangGo, StartLine: 3,
		TaintSig: TaintSignature{SourceParams: map[int]taint.SourceCategory{0: taint.SrcUserInput}},
	})

	for i := 0; i < fanout; i++ {
		bDir := filepath.Join(root, "svc")
		cDir := filepath.Join(root, "store")
		_ = os.MkdirAll(bDir, 0o755)
		_ = os.MkdirAll(cDir, 0o755)
		bFile := filepath.Join(bDir, "b"+twoHopItoa(i)+".go")
		cFile := filepath.Join(cDir, "c"+twoHopItoa(i)+".go")
		bName := "Forward" + twoHopItoa(i)
		cName := "RunQuery" + twoHopItoa(i)

		// B_i forwards its param to C_i. Written to disk.
		_ = os.WriteFile(bFile, []byte(
			"package svc\n\nfunc "+bName+"(q string) {\n\t"+cName+"(q)\n}\n"), 0o644)
		// C_i is the leaf sink. (Its body content isn't read by the lift —
		// only its persisted SinkRef is used — but write it for realism.)
		_ = os.WriteFile(cFile, []byte(
			"package store\n\nfunc "+cName+"(query string) {\n\tdb.Exec(query)\n}\n"), 0o644)

		// B_i: pure forwarder, NO persisted sink (the state the two-hop
		// lift must repair).
		cg.AddNode(&FuncNode{
			ID: bFile + ":" + bName, FilePath: bFile, Name: bName,
			Language: rules.LangGo, StartLine: 3, EndLine: 5,
		})
		// C_i: leaf SQL sink fed by param 0.
		cg.AddNode(&FuncNode{
			ID: cFile + ":" + cName, FilePath: cFile, Name: cName,
			Language: rules.LangGo, StartLine: 3, EndLine: 5,
			TaintSig: TaintSignature{
				SinkCalls: []SinkRef{{SinkCategory: taint.SnkSQLQuery, MethodName: "db.Exec", Line: 4, ArgFromParam: 0}},
			},
		})
		cg.AddEdge(aFile+":Hub", bFile+":"+bName)
		cg.AddEdge(bFile+":"+bName, cFile+":"+cName)

		aBody += "\t" + bName + "(q)\n"
	}
	aBody += "}\n"
	cg.Nodes[aFile+":Hub"].EndLine = 3 + fanout + 1

	contents := map[string]string{aFile: aBody}
	return cg, aFile, contents
}

// freshCopyGraph returns a deep-enough copy of cg's node taint sigs so a
// benchmark iteration's in-memory lift mutations don't carry over to the
// next iteration (the lift is idempotent on an already-lifted graph, so
// without a reset only the FIRST iteration measures real work).
func resetLiftedSinks(cg *CallGraph) {
	for _, n := range cg.Nodes {
		// Clear inherited sinks on the forwarder (B) nodes only — leaf C
		// sinks and the source-param A node stay as configured.
		if len(n.TaintSig.SinkCalls) == 1 && n.TaintSig.SinkCalls[0].OriginFile != "" {
			n.TaintSig.SinkCalls = nil
		}
	}
}

func benchmarkHookHops(b *testing.B, fanout int, twoHop bool) {
	cg, aFile, contents := buildAggregatorGraph(b, fanout)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		resetLiftedSinks(cg)
		b.StartTimer()
		if twoHop {
			LiftSecondHopSinksForFile(cg, aFile, contents)
		}
		_ = WalkCrossFileTaintFlowsForCaller(cg, aFile, contents)
	}
}

func BenchmarkHookTwoHop_OneHop_Fan8(b *testing.B)  { benchmarkHookHops(b, 8, false) }
func BenchmarkHookTwoHop_TwoHop_Fan8(b *testing.B)  { benchmarkHookHops(b, 8, true) }
func BenchmarkHookTwoHop_OneHop_Fan32(b *testing.B) { benchmarkHookHops(b, 32, false) }
func BenchmarkHookTwoHop_TwoHop_Fan32(b *testing.B) { benchmarkHookHops(b, 32, true) }
func BenchmarkHookTwoHop_OneHop_Fan64(b *testing.B) { benchmarkHookHops(b, 64, false) }
func BenchmarkHookTwoHop_TwoHop_Fan64(b *testing.B) { benchmarkHookHops(b, 64, true) }
