package dirscan

// Latency-budget benchmark for the write-time hook cross-file lane.
//
// The lane's hard constraint is bounded added latency per hook
// invocation: load+adopt a multi-MB scan-built graph, incrementally
// re-resolve ONE file's cross-file edges, walk its one-hop pairs, and
// save the graph back. This benchmark builds a synthetic project whose
// persisted graph is ~5MB and times scanner.Scan (the hook entry) with
// the lane ON vs OFF:
//
//	go test ./scanner/dirscan/ -run xxx -bench BenchmarkHookScan -benchtime 20x
//
// ssaflow is disabled in both arms so the delta isolates the lane (Go
// hook scans pay ssaflow regardless; non-Go languages never do).

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/graph"
	"github.com/turenlabs/batou-core/hook"
	"github.com/turenlabs/batou-core/scanner"
	"github.com/turenlabs/batou-rules/rules"
)

// buildBigGraphFixture generates a multi-package Go project on disk,
// builds its call graph directly through the graph API (much faster
// than a full dirscan.Run — the hook timing doesn't depend on how the
// graph was built), runs the FULL cross-file resolve (so the graph
// carries scan-built state), and persists it. Returns the project dir,
// graph path, and the handler file used as the hook edit target.
func buildBigGraphFixture(b *testing.B, packages int) (dir, graphPath, editFile string) {
	b.Helper()
	dir = b.TempDir()
	graphPath = filepath.Join(dir, ".batou", "callgraph.json")

	write := func(rel, body string) {
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			b.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			b.Fatal(err)
		}
	}

	write("go.mod", "module example.com/big\n\ngo 1.21\n")

	cg := graph.NewCallGraph(dir, "")
	update := func(rel, body string) {
		path := filepath.Join(dir, rel)
		write(rel, body)
		graph.UpdateFile(cg, path, body, rules.LangGo)
	}

	// Service packages: one sink func + filler funcs each, so the node
	// count (and persisted JSON size) is realistic.
	for i := 0; i < packages; i++ {
		var sb strings.Builder
		fmt.Fprintf(&sb, "package svc%d\n\nimport \"database/sql\"\n\nvar db *sql.DB\n\n", i)
		fmt.Fprintf(&sb, "func Process(query string) {\n\tdb.Exec(query)\n}\n\n")
		for j := 0; j < 8; j++ {
			fmt.Fprintf(&sb, "func helper%d(v string) string {\n\tout := v + \"-%d\"\n\tfor k := 0; k < %d; k++ {\n\t\tout += \"x\"\n\t}\n\treturn out\n}\n\n", j, j, j+1)
		}
		update(fmt.Sprintf("svc%d/svc.go", i), sb.String())
	}

	// Handler file: the hook edit target. 20 handlers, each calling a
	// different service package's sink func with request input.
	var hb strings.Builder
	hb.WriteString("package web\n\nimport (\n\t\"net/http\"\n\n")
	for i := 0; i < 20; i++ {
		fmt.Fprintf(&hb, "\tsvc%d \"example.com/big/svc%d\"\n", i, i)
	}
	hb.WriteString(")\n\n")
	for i := 0; i < 20; i++ {
		fmt.Fprintf(&hb, "func Handler%d(w http.ResponseWriter, r *http.Request) {\n\tsvc%d.Process(r.URL.Query().Get(\"q\"))\n}\n\n", i, i)
	}
	update("web/handlers.go", hb.String())
	editFile = filepath.Join(dir, "web", "handlers.go")

	// Full cross-file pass + persist — the state `batou scan` leaves behind.
	graph.ResolveCrossFileEdges(cg, dir, nil)
	if err := graph.SaveGraphAt(cg, graphPath); err != nil {
		b.Fatal(err)
	}
	info, err := os.Stat(graphPath)
	if err != nil {
		b.Fatal(err)
	}
	b.Logf("fixture: %d packages, %d nodes, graph file %.1f MB", packages, len(cg.Nodes), float64(info.Size())/(1024*1024))
	return dir, graphPath, editFile
}

func benchmarkHookScan(b *testing.B, crossFile bool) {
	b.Setenv("BATOU_SSAFLOW", "0")
	if !crossFile {
		b.Setenv("BATOU_HOOK_CROSSFILE", "0")
	}
	dir, graphPath, editFile := buildBigGraphFixture(b, 700)

	prev := scanner.CallgraphPathOverride
	scanner.CallgraphPathOverride = graphPath
	defer func() { scanner.CallgraphPathOverride = prev }()

	src, err := os.ReadFile(editFile)
	if err != nil {
		b.Fatal(err)
	}
	edited := strings.Replace(string(src), `Get("q")`, `Get("id")`, 1)
	input := &hook.Input{
		SessionID:     "bench-session",
		Cwd:           dir,
		HookEventName: "PreToolUse",
		ToolName:      "Write",
		ToolInput:     hook.ToolInput{FilePath: editFile, Content: edited},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := scanner.Scan(input)
		if result == nil {
			b.Fatal("nil scan result")
		}
	}
}

// BenchmarkHookScanCrossFileLane measures a hook invocation that adopts
// the ~5MB scan-built graph, restores the edited file's cross-file
// edges, walks its one-hop pairs, and persists the full graph back.
func BenchmarkHookScanCrossFileLane(b *testing.B) {
	benchmarkHookScan(b, true)
}

// BenchmarkHookScanLegacyLane is the pre-lane baseline: session-keyed
// graph (the scan-built file is ignored after the first save), no
// cross-file work.
func BenchmarkHookScanLegacyLane(b *testing.B) {
	benchmarkHookScan(b, false)
}
