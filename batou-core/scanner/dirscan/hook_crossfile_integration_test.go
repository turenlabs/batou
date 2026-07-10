package dirscan

// Integration test for the write-time hook cross-file lane: a graph
// built and persisted by `batou scan` (dirscan.Run) must let a
// subsequent HOOK invocation (scanner.Scan with a hook.Input) surface a
// cross-file taint flow — handler in file A passing request input to a
// SQL sink in file B — that does NOT fire without the persisted graph.
//
// Also pins the safety contract: the hook's graph save must not destroy
// the scan-built cross-file state (nodes, signatures, edges, index).

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/graph"
	"github.com/turenlabs/batou-core/hook"
	"github.com/turenlabs/batou-core/scanner"
	"github.com/turenlabs/batou-rules/rules"
)

const hookCFMainSrc = `package main

import (
	"net/http"

	"example.com/app/storage"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	storage.LoadUser(r.URL.Query().Get("q"))
}
`

const hookCFDBSrc = `package storage

import "database/sql"

var db *sql.DB

func LoadUser(query string) {
	db.Exec(query)
}
`

func writeHookCFFixture(t *testing.T) (dir, mainPath, dbPath string) {
	t.Helper()
	dir = t.TempDir()
	files := map[string]string{
		"go.mod":        "module example.com/app\n\ngo 1.21\n",
		"main.go":       hookCFMainSrc,
		"storage/db.go": hookCFDBSrc,
	}
	for rel, body := range files {
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir, filepath.Join(dir, "main.go"), filepath.Join(dir, "storage", "db.go")
}

// hookScanMain runs the hook pipeline (scanner.Scan) for a Write of
// main.go with a slightly edited body, with the callgraph override
// pointed at graphPath. Restores the override afterward.
func hookScanMain(t *testing.T, dir, mainPath, graphPath, sessionID string) []rules.Finding {
	t.Helper()
	prev := scanner.CallgraphPathOverride
	scanner.CallgraphPathOverride = graphPath
	defer func() { scanner.CallgraphPathOverride = prev }()

	// Edit the handler body so the builder rebuilds the node (the
	// canonical hook situation: Claude just changed this function).
	edited := strings.Replace(hookCFMainSrc, `Get("q")`, `Get("id")`, 1)
	input := &hook.Input{
		SessionID:     sessionID,
		Cwd:           dir,
		HookEventName: "PreToolUse",
		ToolName:      "Write",
		ToolInput: hook.ToolInput{
			FilePath: mainPath,
			Content:  edited,
		},
	}
	result := scanner.Scan(input)
	if result == nil {
		t.Fatalf("scanner.Scan returned nil")
	}
	return result.Findings
}

func findCrossFileSQLFinding(findings []rules.Finding, dbPath string) *rules.Finding {
	for i := range findings {
		f := &findings[i]
		if f.RuleID != "BATOU-INTERPROC-SQL_QUERY" {
			continue
		}
		for _, st := range f.TaintPath {
			if st.Kind == rules.TaintStepSink && st.File == dbPath {
				return f
			}
		}
	}
	return nil
}

func TestHookCrossFileLane_EndToEnd(t *testing.T) {
	// Disable the Go-specific ssaflow Layer-3 engine for this test. With
	// it ON, ssaflow's whole-module analysis ALSO sees this flow and the
	// (line, CWE) dedup merges the interproc finding into the taint-tier
	// winner (correct production behavior — the lanes agree and the
	// winner gets the multi-layer confidence boost). Turning it off
	// isolates the graph-lane mechanism under test — the only cross-file
	// producer for the 15 non-Go languages and for Go when the module
	// doesn't load.
	t.Setenv("BATOU_SSAFLOW", "0")

	dir, mainPath, dbPath := writeHookCFFixture(t)
	graphPath := filepath.Join(dir, ".batou", "callgraph.json")

	// Phase 1: `batou scan` equivalent — builds AND persists the graph
	// with the cross-file finalize pass.
	var out bytes.Buffer
	if err := Run(context.Background(), Options{
		Root:          dir,
		Exts:          []string{".go"},
		Out:           &out,
		ErrOut:        io.Discard,
		CallgraphPath: graphPath,
	}); err != nil {
		t.Fatalf("dirscan Run: %v", err)
	}

	// Sanity: the persisted graph must carry cross-file state and the
	// callee's SQL sink signature — that's what the hook lane consumes.
	persisted, err := graph.LoadGraphAt(graphPath, dir, "")
	if err != nil {
		t.Fatalf("loading persisted graph: %v", err)
	}
	if !persisted.HasCrossFileState() {
		t.Fatalf("scan did not persist cross-file state (PackageIndex empty)")
	}
	calleeID := dbPath + ":LoadUser"
	calleeNode := persisted.GetNode(calleeID)
	if calleeNode == nil {
		t.Fatalf("persisted graph missing callee node %s", calleeID)
	}
	if len(calleeNode.TaintSig.SinkCalls) == 0 {
		t.Fatalf("persisted callee signature has no SinkCalls — fixture or sig computation broken")
	}

	// Phase 2 (control): the hook WITHOUT a persisted graph must not
	// produce the cross-file finding. Point the override at a path with
	// no graph file.
	emptyGraph := filepath.Join(t.TempDir(), "absent.json")
	controlFindings := hookScanMain(t, dir, mainPath, emptyGraph, "hook-session-control")
	if f := findCrossFileSQLFinding(controlFindings, dbPath); f != nil {
		t.Fatalf("control: cross-file finding fired WITHOUT a persisted graph: %+v", *f)
	}

	// Phase 3: the hook WITH the scan-built graph must surface the
	// cross-file SQLi (handler in main.go -> sink in storage/db.go).
	findings := hookScanMain(t, dir, mainPath, graphPath, "hook-session-1")
	f := findCrossFileSQLFinding(findings, dbPath)
	if f == nil {
		var ids []string
		for _, ff := range findings {
			ids = append(ids, ff.RuleID)
		}
		t.Fatalf("hook scan with persisted graph produced no cross-file SQL finding; got rules: %v", ids)
	}
	if f.CWEID != "CWE-89" {
		t.Errorf("cross-file finding CWEID = %q, want CWE-89", f.CWEID)
	}
	if f.FilePath != mainPath {
		t.Errorf("cross-file finding FilePath = %q, want the edited caller file %q", f.FilePath, mainPath)
	}

	// Determinism: a second identical hook invocation reproduces the finding.
	again := hookScanMain(t, dir, mainPath, graphPath, "hook-session-2")
	if findCrossFileSQLFinding(again, dbPath) == nil {
		t.Errorf("second hook invocation lost the cross-file finding")
	}

	// Phase 4 (safety): the hook saves the graph after scanning; the
	// scan-built cross-file state must survive — adopted, updated, not
	// clobbered.
	after, err := graph.LoadGraphAt(graphPath, dir, "")
	if err != nil {
		t.Fatalf("reloading graph after hook save: %v", err)
	}
	if after.SessionID != "" {
		t.Errorf("hook save changed SessionID to %q; must stay \"\" so the next batou scan warm-starts", after.SessionID)
	}
	if !after.HasCrossFileState() {
		t.Fatalf("hook save destroyed the scan-built cross-file state")
	}
	if after.GetNode(calleeID) == nil {
		t.Fatalf("hook save lost the callee node from the other file")
	}
	if len(after.GetNode(calleeID).TaintSig.SinkCalls) == 0 {
		t.Errorf("hook save lost the callee's sink signature")
	}
	handlerID := mainPath + ":Handler"
	handler := after.GetNode(handlerID)
	if handler == nil {
		t.Fatalf("hook save lost the edited file's node")
	}
	found := false
	for _, c := range handler.Calls {
		if c == calleeID {
			found = true
		}
	}
	if !found {
		t.Errorf("persisted graph lost the restored cross-file edge %s -> %s", handlerID, calleeID)
	}
}

// TestHookCrossFileLane_KillSwitch verifies BATOU_HOOK_CROSSFILE=0
// restores the legacy behavior (session-keyed graph, no cross-file
// findings) even with a scan-built graph present.
func TestHookCrossFileLane_KillSwitch(t *testing.T) {
	dir, mainPath, dbPath := writeHookCFFixture(t)
	graphPath := filepath.Join(dir, ".batou", "callgraph.json")

	var out bytes.Buffer
	if err := Run(context.Background(), Options{
		Root:          dir,
		Exts:          []string{".go"},
		Out:           &out,
		ErrOut:        io.Discard,
		CallgraphPath: graphPath,
	}); err != nil {
		t.Fatalf("dirscan Run: %v", err)
	}

	t.Setenv("BATOU_HOOK_CROSSFILE", "0")
	findings := hookScanMain(t, dir, mainPath, graphPath, "hook-session-off")
	if f := findCrossFileSQLFinding(findings, dbPath); f != nil {
		t.Errorf("kill switch active but cross-file finding fired: %+v", *f)
	}
}
