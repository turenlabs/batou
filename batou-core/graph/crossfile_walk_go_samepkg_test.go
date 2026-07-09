package graph

import (
	"path/filepath"
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// TestGoResolver_ResolveBareSamePackageCrossFile is the load-bearing test
// for CH2-go-same-package-resolve. Two files in the SAME Go package live in
// the same directory: handler.go makes a BARE same-package call `helper(...)`
// to a function `func helper(q string)` defined in helper.go. Go makes that
// top-level func visible across the package's files without an import, so the
// same-file extraction pass (buildGoNodes) can't wire the edge — only the
// cross-file resolver can.
//
// WITHOUT the fix goResolver.ResolveCall returns an empty result for a bare
// identifier, so the A→B edge never resolves in the cross-file lane, the
// CalledBy back-edge is never created, and WalkCrossFileTaintFlows finds no
// flow. WITH the fix the bare call resolves to the sibling-file func, the
// edge and back-edge appear, and the cross-file taint walk surfaces the
// SQL-injection flow.
func TestGoResolver_ResolveBareSamePackageCrossFile(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")

	// Both files in the SAME directory => SAME package "app" => same Go
	// PackageIndex key (the module's import path for that directory).
	handlerPath := filepath.Join(root, "handler.go")
	helperPath := filepath.Join(root, "helper.go")

	// Caller: Handler. It calls the bare same-package func `helper`. The
	// same-file pass leaves "helper" in RawCalls because the definition is
	// in helper.go, a different file. SourceParams marks the *http.Request
	// param as a user-input source so the walk's Path-A taint check passes.
	cg.AddNode(&FuncNode{
		ID:        handlerPath + ":Handler",
		FilePath:  handlerPath,
		Name:      "Handler",
		Package:   "app",
		Language:  rules.LangGo,
		StartLine: 8,
		EndLine:   10,
		RawCalls:  []string{"helper"},
		TaintSig: TaintSignature{
			SourceParams: map[int]taint.SourceCategory{1: taint.SrcUserInput},
		},
	})

	// Callee: helper, defined in the sibling file. It hands its param 0 to a
	// SQL sink, so the cross-file walk can produce a CWE-89 finding.
	cg.AddNode(&FuncNode{
		ID:        helperPath + ":helper",
		FilePath:  helperPath,
		Name:      "helper",
		Package:   "app",
		Language:  rules.LangGo,
		StartLine: 5,
		EndLine:   7,
		TaintSig: TaintSignature{
			SourceParams:  map[int]taint.SourceCategory{0: taint.SrcUserInput},
			TaintedParams: map[int][]taint.SourceCategory{0: {taint.SrcUserInput}},
			SinkCalls: []SinkRef{
				{SinkCategory: taint.SnkSQLQuery, MethodName: "db.Exec", Line: 6, ArgFromParam: 0},
			},
		},
	})

	cg.ModulePaths = map[rules.Language]string{rules.LangGo: "example.com/proj"}
	cg.ModuleRoots = map[rules.Language]string{rules.LangGo: root}

	contents := map[string][]byte{
		handlerPath: []byte(`package app

import "net/http"

// Handler reads a query param and forwards it to the same-package helper,
// which is defined in helper.go (a DIFFERENT file, same package).
func Handler(w http.ResponseWriter, r *http.Request) {
	helper(r.URL.Query().Get("q"))
}
`),
		helperPath: []byte(`package app

import "database/sql"

func helper(q string) {
	db.Exec(q)
}

var db *sql.DB
`),
	}

	stats := ResolveCrossFileEdges(cg, root, contents)

	// --- Assertion 1: the cross-file edge resolves (this is what the fix
	// enables; without it CrossFileEdges stays 0 here). ---
	if stats.CrossFileEdges != 1 {
		t.Fatalf("CrossFileEdges = %d, want 1 (bare same-package cross-file call should resolve); stats=%+v", stats.CrossFileEdges, stats)
	}

	caller := cg.GetNode(handlerPath + ":Handler")
	if caller == nil {
		t.Fatal("caller node missing")
	}
	wantCallee := helperPath + ":helper"
	if !containsStr(caller.Calls, wantCallee) {
		t.Fatalf("caller.Calls missing %q (got %v)", wantCallee, caller.Calls)
	}

	// --- Assertion 2: the CalledBy back-edge exists (the cross-file taint
	// walk iterates callees by CalledBy). ---
	callee := cg.GetNode(wantCallee)
	if callee == nil || !containsStr(callee.CalledBy, handlerPath+":Handler") {
		t.Fatalf("CalledBy back-edge missing on helper node: %+v", callee)
	}

	// --- Assertion 3: the cross-file SQL-injection flow is found. ---
	strContents := map[string]string{
		handlerPath: string(contents[handlerPath]),
		helperPath:  string(contents[helperPath]),
	}
	var walkStats CrossFileWalkStats
	findings := WalkCrossFileTaintFlowsWithStats(cg, strContents, &walkStats)
	if walkStats.Pairs != 1 {
		t.Fatalf("walk Pairs = %d, want 1 (the resolved cross-file pair)", walkStats.Pairs)
	}
	foundSQL := false
	for _, f := range findings {
		if f.CWEID == "CWE-89" {
			foundSQL = true
			break
		}
	}
	if !foundSQL {
		t.Fatalf("expected a CWE-89 cross-file flow finding; got %d findings: %+v", len(findings), findings)
	}
}
