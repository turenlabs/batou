// Cross-file Python interproc walker tests (PR-Gpy).
//
// These tests exercise the full Python cross-file pipeline:
//   1. buildPythonNodes registers FuncNodes for each .py file.
//   2. ResolveCrossFileEdges (via per-file import resolution) wires up
//      caller→callee edges between the files.
//   3. WalkCrossFileTaintFlows dispatches to AnalyzeCallerImpactPython
//      for Python callees and emits BATOU-INTERPROC-<CAT> findings.
//
// Negative tests assert that hardcoded args, sanitized args, and pure
// (no-source) callers produce zero findings, mirroring the Go path's
// FP suppression behaviour from PR-G.

package graph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// pythonScanFixture builds a tiny project: writes files (auto-adding
// a pyproject.toml so the Python resolver can anchor the project
// root), builds nodes, resolves cross-file edges, and returns the
// populated CallGraph plus the absolute path to each file by basename.
// Used by every test below.
//
// The pyproject manifest is required: without it the Python resolver
// falls through to Pass 3 (any .py file), which doesn't populate a
// module path — and resolve.go's importPathForNode then can't key the
// PackageIndex consistently with what `from X import Y` lookups need.
func pythonScanFixture(t *testing.T, files map[string]string) (*CallGraph, map[string]string) {
	t.Helper()
	root := t.TempDir()
	if _, present := files["pyproject.toml"]; !present {
		files["pyproject.toml"] = "[project]\nname = \"proj\"\n"
	}
	if err := writeFiles(t, root, files); err != nil {
		t.Fatalf("writeFiles: %v", err)
	}
	cg := NewCallGraph(root, "test")
	paths := map[string]string{}
	contents := map[string][]byte{}
	for rel, content := range files {
		abs := filepath.Join(root, rel)
		paths[rel] = abs
		if !strings.HasSuffix(rel, ".py") {
			continue
		}
		buildPythonNodes(cg, abs, content, nil)
		contents[abs] = []byte(content)
	}
	// Resolve cross-file edges so the walker has caller→callee pairs.
	// Pass file contents so ExtractScope doesn't have to re-read from
	// disk (mirrors the dirscan finalize path).
	ResolveCrossFileEdges(cg, root, contents)
	return cg, paths
}

// TestPythonCrossFile_TwoHopChain_CommandExec exercises the canonical
// 2-hop chain that PR-Hpy's signature propagation unlocks:
//
//	runners.py :: def run_cmd(cmd): subprocess.run(cmd, shell=True)
//	helpers.py :: def forward(x):   run_cmd(x)
//	app.py     :: def handle(request: Request):
//	                forward(request)
//
// PR-Gpy alone catches only `handle -> run_cmd` style direct calls
// (1-hop: caller -> callee that has the sink). Here the sink is one hop
// deeper: handle -> forward (delegate, no direct sink) -> run_cmd
// (sink). For the cross-file walker to fire on handle -> forward,
// forward's TaintSig.SinkCalls must contain run_cmd's subprocess.run
// sink. That's what PropagateSignaturesAcrossCallgraph delivers: it
// lifts run_cmd's sink UP to forward (because forward passes its own
// param x to run_cmd) so the next walker pass treats forward as if it
// were a direct sink, and emits a BATOU-INTERPROC-COMMAND_EXEC finding
// at the handle -> forward call site.
func TestPythonCrossFile_TwoHopChain_CommandExec(t *testing.T) {
	cg, paths := pythonScanFixture(t, map[string]string{
		"runners.py": `import subprocess

def run_cmd(cmd):
    subprocess.run(cmd, shell=True)
`,
		"helpers.py": `from runners import run_cmd

def forward(x):
    run_cmd(x)
`,
		"app.py": `from flask import Request
from helpers import forward

def handle(request: Request):
    forward(request)
`,
	})

	// Pre-warm typed signatures so SourceParams + (where applicable)
	// TaintedReturns are populated on each node. The dirscan finalize
	// path does this implicitly via PropagateInterprocTyped; here we
	// invoke ComputeTaintSigTyped directly per node.
	primePythonSigs(t, cg, paths)

	// Mirror the dirscan finalize step: lift downstream sinks up the
	// call graph before walking. PropagateSignaturesAcrossCallgraph
	// pre-populates each Python leaf's SinkCalls (ensurePythonCalleeSinks)
	// then iterates fixed-point so middle nodes like handle() inherit
	// run_cmd's subprocess.run sink.
	propStats := PropagateSignaturesAcrossCallgraph(cg, nil)
	if propStats.SinksLifted == 0 {
		t.Fatalf("expected sig propagation to lift at least one sink; got %+v", propStats)
	}

	var stats CrossFileWalkStats
	findings := WalkCrossFileTaintFlowsWithStats(cg, nil, &stats)

	if stats.Pairs == 0 {
		t.Fatalf("expected at least one cross-file pair, got 0; cg.Nodes=%d", len(cg.Nodes))
	}
	cmdFindings := filterFindingsByRule(findings, "BATOU-INTERPROC-COMMAND_EXEC")
	if len(cmdFindings) == 0 {
		t.Fatalf("expected at least one BATOU-INTERPROC-COMMAND_EXEC finding, got %d findings: %v",
			len(findings), findingRuleIDs(findings))
	}
	// At least one finding must reference the subprocess.run sink in
	// runners.py — that's the canonical leaf for the 2-hop chain. The
	// lifted sink that fires from handle→run_cmd carries the (via X)
	// annotation in MethodName and points the sink-step file to
	// run_cmd's file because that's where the deep sink lives.
	sinkSeen := false
	for _, f := range cmdFindings {
		for _, st := range f.TaintPath {
			if st.Kind == rules.TaintStepSink && st.File == paths["runners.py"] {
				sinkSeen = true
				break
			}
		}
	}
	if !sinkSeen {
		t.Errorf("no finding had a sink step in runners.py; findings=%+v", cmdFindings)
	}
}

// TestPythonCrossFile_ThreeHopChain_CommandExec extends the 2-hop test
// one level deeper: handler -> middleware -> helper -> sink. Every
// intermediate node passes its own first parameter to the next call,
// so PR-Hpy's signature propagation should converge by lifting the
// subprocess.run sink through middleware then through helper, and the
// cross-file walker should emit a BATOU-INTERPROC-COMMAND_EXEC finding
// at the handle -> middleware call site whose TaintPath reaches all
// the way down to runners.py.
//
// This is the canonical multi-hop chain Go covers in
// TestPropagation_ConvergesInFewIterations; the Python fixture mirrors
// the same shape (F(x) -> G(x) -> H(x) sink).
func TestPythonCrossFile_ThreeHopChain_CommandExec(t *testing.T) {
	cg, paths := pythonScanFixture(t, map[string]string{
		"runners.py": `import subprocess

def run_cmd(cmd):
    subprocess.run(cmd, shell=True)
`,
		"helpers.py": `from runners import run_cmd

def forward(x):
    run_cmd(x)
`,
		"middleware.py": `from helpers import forward

def middleware(y):
    forward(y)
`,
		"app.py": `from flask import Request
from middleware import middleware

def handle(request: Request):
    middleware(request)
`,
	})

	primePythonSigs(t, cg, paths)

	propStats := PropagateSignaturesAcrossCallgraph(cg, nil)
	// Two distinct lifts: run_cmd -> forward, then forward -> middleware.
	// (handle's request is source-typed so the walker fires Path A
	// directly without needing a third lift onto handle.)
	if propStats.SinksLifted < 2 {
		t.Fatalf("expected sig propagation to lift >= 2 sinks (run_cmd->forward, forward->middleware); got %+v",
			propStats)
	}

	findings := WalkCrossFileTaintFlows(cg, nil)
	cmdFindings := filterFindingsByRule(findings, "BATOU-INTERPROC-COMMAND_EXEC")
	if len(cmdFindings) == 0 {
		t.Fatalf("expected at least one BATOU-INTERPROC-COMMAND_EXEC finding through 3-hop chain; got %d findings: %v",
			len(findings), findingRuleIDs(findings))
	}
	// Some finding must point at the actual subprocess.run sink in
	// runners.py — the OriginFile carry-through is what guarantees the
	// leaf is preserved through the chain.
	sinkSeen := false
	for _, f := range cmdFindings {
		for _, st := range f.TaintPath {
			if st.Kind == rules.TaintStepSink && st.File == paths["runners.py"] {
				sinkSeen = true
				break
			}
		}
	}
	if !sinkSeen {
		t.Errorf("no finding's sink step pointed at runners.py through the 3-hop chain; findings=%+v", cmdFindings)
	}
}

// TestPythonCrossFile_SingleHop_SQLExecute covers the 1-hop case: the
// handler calls a SQL-using helper directly. The helper takes a string
// param and passes it to cursor.execute(); the handler reads
// request.args.get() and forwards it. Expected:
// BATOU-INTERPROC-SQL_QUERY finding.
func TestPythonCrossFile_SingleHop_SQLExecute(t *testing.T) {
	cg, paths := pythonScanFixture(t, map[string]string{
		"db.py": `def find_user(name):
    cursor.execute("SELECT * FROM users WHERE name='" + name + "'")
`,
		"app.py": `from flask import Request
from db import find_user

def handle(request: Request):
    find_user(request.args.get('name'))
`,
	})

	primePythonSigs(t, cg, paths)

	findings := WalkCrossFileTaintFlows(cg, nil)
	sqlFindings := filterFindingsByRule(findings, "BATOU-INTERPROC-SQL_QUERY")
	if len(sqlFindings) == 0 {
		t.Fatalf("expected at least one BATOU-INTERPROC-SQL_QUERY finding, got %d findings: %v",
			len(findings), findingRuleIDs(findings))
	}
}

// TestPythonCrossFile_Sanitized_NoFinding mirrors PR-HH: a handler
// passes user input through shlex.quote() (a known sanitizer) before
// handing it off to a sql-using helper. The cross-file walker must
// NOT emit a finding — the input is wrapped by a known sanitizer at
// the call site.
func TestPythonCrossFile_Sanitized_NoFinding(t *testing.T) {
	cg, paths := pythonScanFixture(t, map[string]string{
		"db.py": `def find_user(name):
    cursor.execute("SELECT * FROM users WHERE name='" + name + "'")
`,
		"app.py": `import shlex
from flask import Request
from db import find_user

def handle(request: Request):
    safe = shlex.quote(request.args.get('name'))
    find_user(safe)
`,
	})

	primePythonSigs(t, cg, paths)

	findings := WalkCrossFileTaintFlows(cg, nil)
	sqlFindings := filterFindingsByRule(findings, "BATOU-INTERPROC-SQL_QUERY")
	if len(sqlFindings) != 0 {
		t.Errorf("sanitized input should not produce a SQL_QUERY finding; got %d: %+v",
			len(sqlFindings), sqlFindings)
	}
}

// TestPythonCrossFile_HardcodedArg_NoFinding asserts that a caller
// passing a hardcoded string literal to a sink-bearing callee does NOT
// produce an interproc finding — there's no tainted source involved.
func TestPythonCrossFile_HardcodedArg_NoFinding(t *testing.T) {
	cg, paths := pythonScanFixture(t, map[string]string{
		"db.py": `def find_user(name):
    cursor.execute("SELECT * FROM users WHERE name='" + name + "'")
`,
		"app.py": `from db import find_user

def admin_seed():
    find_user("alice")
`,
	})

	primePythonSigs(t, cg, paths)

	findings := WalkCrossFileTaintFlows(cg, nil)
	sqlFindings := filterFindingsByRule(findings, "BATOU-INTERPROC-SQL_QUERY")
	if len(sqlFindings) != 0 {
		t.Errorf("hardcoded arg should not produce a SQL_QUERY finding; got %d: %+v",
			len(sqlFindings), sqlFindings)
	}
}

// TestPythonCrossFile_CalleeLanguageRoute pins the dispatch in
// crossfile_walk.go: a Python callee MUST go through
// AnalyzeCallerImpactPython, not the Go walker. The pin is indirect:
// the Go walker would never recognise `subprocess.run` (it's not in
// sinkCallPatterns) so an emitted COMMAND_EXEC finding can only come
// from the Python path. If this test starts failing with "got 0
// findings" check whether the language switch in
// WalkCrossFileTaintFlows was removed.
func TestPythonCrossFile_CalleeLanguageRoute(t *testing.T) {
	cg, paths := pythonScanFixture(t, map[string]string{
		"runners.py": `import subprocess

def run_cmd(cmd):
    subprocess.run(cmd, shell=True)
`,
		"app.py": `from flask import Request
from runners import run_cmd

def handle(request: Request):
    run_cmd(request.args.get('q'))
`,
	})

	primePythonSigs(t, cg, paths)

	findings := WalkCrossFileTaintFlows(cg, nil)
	if filterFindingsByRule(findings, "BATOU-INTERPROC-COMMAND_EXEC") == nil {
		t.Fatalf("expected BATOU-INTERPROC-COMMAND_EXEC via Python route; got %v",
			findingRuleIDs(findings))
	}
	// Every emitted finding's Language must be Python — never Go.
	for _, f := range findings {
		if f.Language != rules.LangPython && f.Language != "" {
			t.Errorf("finding has wrong Language %q (want LangPython): %+v", f.Language, f)
		}
	}
}

// TestEnsurePythonCalleeSinks_LazyPopulates checks that a Python
// callee arriving at the walker with empty SinkCalls gets them filled
// from the catalog. This is the "fix-forward" guarantee the Go path
// achieves through sig_propagation but Python doesn't have yet.
func TestEnsurePythonCalleeSinks_LazyPopulates(t *testing.T) {
	root := t.TempDir()
	runners := filepath.Join(root, "runners.py")
	if err := os.WriteFile(runners, []byte(`import subprocess

def run_cmd(cmd):
    subprocess.run(cmd, shell=True)
`), 0o644); err != nil {
		t.Fatal(err)
	}
	node := &FuncNode{
		ID:        runners + ":run_cmd",
		FilePath:  runners,
		Name:      "run_cmd",
		Language:  rules.LangPython,
		StartLine: 3,
		EndLine:   4,
	}
	if len(node.TaintSig.SinkCalls) != 0 {
		t.Fatalf("precondition: SinkCalls should be empty, got %d", len(node.TaintSig.SinkCalls))
	}

	ensurePythonCalleeSinks(nil, node)

	if len(node.TaintSig.SinkCalls) == 0 {
		t.Fatalf("ensurePythonCalleeSinks did not populate SinkCalls; node.TaintSig=%+v", node.TaintSig)
	}
	gotCommand := false
	for _, s := range node.TaintSig.SinkCalls {
		if s.SinkCategory == taint.SnkCommand {
			gotCommand = true
			break
		}
	}
	if !gotCommand {
		t.Errorf("expected a SnkCommand SinkRef from subprocess.run; got %+v", node.TaintSig.SinkCalls)
	}
}

// TestFindPythonCallSites_PositionalAndKeyword pins the tree-sitter
// arg extractor. A call like `helper(x, name=y)` must extract `x` as
// arg 0 and `name=y` as a keyword. The cross-file walker keys
// Path A on the positional list, but the keyword map is preserved for
// future refinement.
func TestFindPythonCallSites_PositionalAndKeyword(t *testing.T) {
	content := `def caller():
    helper("x", name="alice", q=request.args.get("q"))
`
	caller := &FuncNode{
		Name:      "caller",
		StartLine: 1,
		EndLine:   3,
	}
	sites := findPythonCallSites(content, caller, "helper")
	if len(sites) != 1 {
		t.Fatalf("got %d call sites, want 1", len(sites))
	}
	cs := sites[0]
	if len(cs.args) != 1 || cs.args[0] != `"x"` {
		t.Errorf("positional args = %v, want [\"x\"]", cs.args)
	}
	if cs.keywordArg["name"] != `"alice"` {
		t.Errorf("kw[name] = %q, want \"alice\"", cs.keywordArg["name"])
	}
	if !strings.Contains(cs.keywordArg["q"], "request.args.get") {
		t.Errorf("kw[q] = %q, want to contain request.args.get", cs.keywordArg["q"])
	}
}

// TestIsArgTaintedInPythonCaller_BackwardTrace covers the assignment-
// tracing branch: the call's arg is a local variable that was bound to
// a request expression on a previous line.
func TestIsArgTaintedInPythonCaller_BackwardTrace(t *testing.T) {
	body := []string{
		`def handler(request):`,
		`    raw = request.args.get('q')`,
		`    helper(raw)`,
	}
	if !isArgTaintedInPythonCaller("raw", body, 2, &TaintSignature{}) {
		t.Errorf("expected raw to trace back to request.args.get(...)")
	}
}

// TestIsArgTaintedInPythonCaller_SanitizedAssignmentNotTainted: if the
// assignment to argVar passes through a sanitizer the arg should NOT
// be reported as tainted (and the walker must not emit a finding).
func TestIsArgTaintedInPythonCaller_SanitizedAssignmentNotTainted(t *testing.T) {
	body := []string{
		`def handler(request):`,
		`    raw = html.escape(request.args.get('q'))`,
		`    helper(raw)`,
	}
	if isArgTaintedInPythonCaller("raw", body, 2, &TaintSignature{}) {
		t.Errorf("expected raw not to be tainted: it was wrapped in html.escape")
	}
}

// --- Helpers ---

// primePythonSigs walks every Python FuncNode in the graph and runs
// ComputeTaintSigTyped on it so the typed Params + SourceParams are
// available before the cross-file walk. Mirrors what the dirscan
// finalize path does via PropagateInterprocTyped.
func primePythonSigs(t *testing.T, cg *CallGraph, paths map[string]string) {
	t.Helper()
	contents := map[string]string{}
	for _, abs := range paths {
		data, err := os.ReadFile(abs)
		if err != nil {
			t.Fatalf("read %s: %v", abs, err)
		}
		contents[abs] = string(data)
	}
	for _, n := range cg.Nodes {
		if n.Language != rules.LangPython {
			continue
		}
		content, ok := contents[n.FilePath]
		if !ok {
			continue
		}
		n.TaintSig = ComputeTaintSigTyped(n, content, rules.LangPython, nil, nil, nil)
	}
}

// filterFindingsByRule returns the subset of findings whose RuleID
// equals ruleID. Returns nil (not []) when none match so the caller's
// "if filterFindingsByRule(...) == nil" check is unambiguous.
func filterFindingsByRule(findings []rules.Finding, ruleID string) []rules.Finding {
	var out []rules.Finding
	for _, f := range findings {
		if f.RuleID == ruleID {
			out = append(out, f)
		}
	}
	return out
}

// findingRuleIDs returns the ordered list of RuleIDs from a finding
// slice. Used in error messages so failures show what WAS emitted.
func findingRuleIDs(findings []rules.Finding) []string {
	out := make([]string, len(findings))
	for i, f := range findings {
		out[i] = f.RuleID
	}
	return out
}
