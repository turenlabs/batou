// Cross-file JavaScript / TypeScript interproc walker tests (PR-Gjs).
//
// These tests exercise the full JS/TS cross-file pipeline:
//   1. buildJSNodes registers FuncNodes for each .js / .ts file.
//   2. ResolveCrossFileEdges (via per-file import resolution) wires up
//      caller→callee edges between the files.
//   3. WalkCrossFileTaintFlows dispatches to AnalyzeCallerImpactJavaScript
//      for JS/TS callees and emits BATOU-INTERPROC-<CAT> findings.
//
// Negative tests assert that sanitized args and pure (no-source) shapes
// produce zero findings, mirroring the Python path's FP suppression.
//
// JS-specific notes vs. the Python equivalent:
//   - There is no `pyproject.toml` analog needed; package.json is optional
//     for relative-import resolution.
//   - Tree-sitter call nodes are `call_expression` not `call`, and arrow
//     functions live under `variable_declarator` (lexical_declaration).
//   - The JS extractor doesn't yet flag IsSourceType (PR-BBjs adds that);
//     these tests use direct source expressions in arg position
//     (`helper(req.body.q)`) so detection lands via javascriptSourceExprRe.

package graph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// javascriptScanFixture builds a tiny project: writes files, builds
// JS/TS FuncNodes, resolves cross-file edges, and returns the populated
// CallGraph plus the absolute path to each file by basename.
//
// Files ending in `.ts` / `.tsx` are processed as TypeScript; everything
// else with a JS-family extension goes through LangJavaScript. A
// minimal `package.json` is added when no JS manifest is present so the
// resolver's ProjectRoot anchors cleanly.
func javascriptScanFixture(t *testing.T, files map[string]string) (*CallGraph, map[string]string) {
	t.Helper()
	root := t.TempDir()
	if _, present := files["package.json"]; !present {
		files["package.json"] = `{"name":"proj","version":"1.0.0"}` + "\n"
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
		ext := filepath.Ext(rel)
		var lang rules.Language
		switch ext {
		case ".js", ".mjs", ".cjs", ".jsx":
			lang = rules.LangJavaScript
		case ".ts", ".tsx":
			lang = rules.LangTypeScript
		default:
			continue
		}
		buildJSNodes(cg, abs, content, lang, nil)
		contents[abs] = []byte(content)
	}
	ResolveCrossFileEdges(cg, root, contents)
	return cg, paths
}

// primeJavaScriptSigs walks every JS/TS FuncNode in the graph and runs
// ComputeTaintSigTyped on it so the typed Params + SourceParams are
// available before the cross-file walk. Mirrors primePythonSigs.
func primeJavaScriptSigs(t *testing.T, cg *CallGraph, paths map[string]string) {
	t.Helper()
	contents := map[string]string{}
	for _, abs := range paths {
		data, err := readTestFile(abs)
		if err != nil {
			t.Fatalf("read %s: %v", abs, err)
		}
		contents[abs] = data
	}
	for _, n := range cg.Nodes {
		if n.Language != rules.LangJavaScript && n.Language != rules.LangTypeScript {
			continue
		}
		content, ok := contents[n.FilePath]
		if !ok {
			continue
		}
		n.TaintSig = ComputeTaintSigTyped(n, content, n.Language, nil, nil, nil)
	}
}

// readTestFile is a tiny helper to read a file's contents to a string.
func readTestFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// TestJavaScriptCrossFile_SingleHop_Eval covers the canonical 1-hop
// case: a handler calls a helper directly. The helper takes a string
// param and passes it into eval(); the handler reads `req.body.code`
// and forwards it. Expected: BATOU-INTERPROC-CODE_EVAL finding.
func TestJavaScriptCrossFile_SingleHop_Eval(t *testing.T) {
	cg, paths := javascriptScanFixture(t, map[string]string{
		"helper.js": `function runScript(code) {
  return eval(code);
}
module.exports = { runScript };
`,
		"app.js": `const { runScript } = require('./helper');
function handle(req, res) {
  runScript(req.body.code);
}
module.exports = { handle };
`,
	})
	primeJavaScriptSigs(t, cg, paths)

	findings := WalkCrossFileTaintFlows(cg, nil)
	evalFindings := filterFindingsByRule(findings, "BATOU-INTERPROC-CODE_EVAL")
	if len(evalFindings) == 0 {
		t.Fatalf("expected BATOU-INTERPROC-CODE_EVAL finding via require/CommonJS shape; got %d findings: %v",
			len(findings), findingRuleIDs(findings))
	}
	// At least one finding's sink step must point at helper.js.
	sinkSeen := false
	for _, f := range evalFindings {
		for _, st := range f.TaintPath {
			if st.Kind == rules.TaintStepSink && st.File == paths["helper.js"] {
				sinkSeen = true
				break
			}
		}
	}
	if !sinkSeen {
		t.Errorf("no finding had a sink step in helper.js; findings=%+v", evalFindings)
	}
}

// TestJavaScriptCrossFile_SingleHop_CommandExec covers a caller passing
// a tainted arg to a callee that forwards it to `child_process.exec()`.
func TestJavaScriptCrossFile_SingleHop_CommandExec(t *testing.T) {
	cg, paths := javascriptScanFixture(t, map[string]string{
		"runner.js": `const child_process = require('child_process');
function runShell(cmd) {
  child_process.exec(cmd);
}
module.exports = { runShell };
`,
		"app.js": `const { runShell } = require('./runner');
function handle(req, res) {
  runShell(req.body.cmd);
}
module.exports = { handle };
`,
	})
	primeJavaScriptSigs(t, cg, paths)

	findings := WalkCrossFileTaintFlows(cg, nil)
	cmdFindings := filterFindingsByRule(findings, "BATOU-INTERPROC-COMMAND_EXEC")
	if len(cmdFindings) == 0 {
		t.Fatalf("expected BATOU-INTERPROC-COMMAND_EXEC finding; got %d findings: %v",
			len(findings), findingRuleIDs(findings))
	}
	// Every emitted finding's Language must be JS / TS — never Go.
	for _, f := range findings {
		if f.Language != "" && f.Language != rules.LangJavaScript && f.Language != rules.LangTypeScript {
			t.Errorf("finding has wrong Language %q: %+v", f.Language, f)
		}
	}
}

// TestJavaScriptCrossFile_Sanitized_NoFinding asserts that wrapping the
// user input in `encodeURIComponent(...)` before passing it across the
// boundary suppresses the finding. Same FP-control story as PR-HH.
func TestJavaScriptCrossFile_Sanitized_NoFinding(t *testing.T) {
	cg, paths := javascriptScanFixture(t, map[string]string{
		"runner.js": `const child_process = require('child_process');
function runShell(cmd) {
  child_process.exec(cmd);
}
module.exports = { runShell };
`,
		"app.js": `const { runShell } = require('./runner');
function handle(req, res) {
  const safe = encodeURIComponent(req.body.cmd);
  runShell(safe);
}
module.exports = { handle };
`,
	})
	primeJavaScriptSigs(t, cg, paths)

	findings := WalkCrossFileTaintFlows(cg, nil)
	cmdFindings := filterFindingsByRule(findings, "BATOU-INTERPROC-COMMAND_EXEC")
	if len(cmdFindings) != 0 {
		t.Errorf("sanitized input should not produce a COMMAND_EXEC finding; got %d: %+v",
			len(cmdFindings), cmdFindings)
	}
}

// TestJavaScriptCrossFile_TaintedReturn_SqlSink covers Path B: a callee
// returns user-controlled data; the caller stores it and forwards it to
// a SQL sink.
//
// The TaintedReturns map is populated AUTOMATICALLY by ensureJavaScript-
// CalleeReturns (scanning `return req.body.q` in the callee body) — no
// planted test data. This is the regression proof that the producer half
// is wired: if the auto-seed regresses, this test goes red.
func TestJavaScriptCrossFile_TaintedReturn_SqlSink(t *testing.T) {
	cg, paths := javascriptScanFixture(t, map[string]string{
		"input.js": `function readInput(req) {
  return req.body.q;
}
module.exports = { readInput };
`,
		"app.js": `const { readInput } = require('./input');
const db = require('./db');
function handle(req, res) {
  const userInput = readInput(req);
  db.query("SELECT * FROM t WHERE x='" + userInput + "'");
}
module.exports = { handle };
`,
		"db.js": `module.exports = { query: function(q) { return q; } };
`,
	})
	primeJavaScriptSigs(t, cg, paths)

	findings := WalkCrossFileTaintFlows(cg, nil)
	sqlFindings := filterFindingsByRule(findings, "BATOU-INTERPROC-SQL_QUERY")
	if len(sqlFindings) == 0 {
		t.Fatalf("expected BATOU-INTERPROC-SQL_QUERY via tainted-return Path B (auto-seeded); got %d findings: %v",
			len(findings), findingRuleIDs(findings))
	}
}

// TestJavaScriptCrossFile_ESMImport_Eval covers an ESM caller chain:
// `import { handler } from './ctrl'` then the route handler forwards
// `req.body.code` to a helper that runs eval(). Mirrors a typical
// Express-app file layout using modern module syntax.
func TestJavaScriptCrossFile_ESMImport_Eval(t *testing.T) {
	cg, paths := javascriptScanFixture(t, map[string]string{
		"ctrl.js": `export function runScript(code) {
  return eval(code);
}
`,
		"app.js": `import { runScript } from './ctrl';
export function handle(req, res) {
  runScript(req.body.code);
}
`,
	})
	primeJavaScriptSigs(t, cg, paths)

	findings := WalkCrossFileTaintFlows(cg, nil)
	evalFindings := filterFindingsByRule(findings, "BATOU-INTERPROC-CODE_EVAL")
	if len(evalFindings) == 0 {
		t.Fatalf("expected BATOU-INTERPROC-CODE_EVAL via ESM import; got %d findings: %v",
			len(findings), findingRuleIDs(findings))
	}
	sinkSeen := false
	for _, f := range evalFindings {
		for _, st := range f.TaintPath {
			if st.Kind == rules.TaintStepSink && st.File == paths["ctrl.js"] {
				sinkSeen = true
				break
			}
		}
	}
	if !sinkSeen {
		t.Errorf("no finding had a sink step in ctrl.js; findings=%+v", evalFindings)
	}
}

// TestJavaScriptCrossFile_TypeScript_CustomInterfaceParam_NoFinding
// pins the PR-CATjs-6 fix: an exported TS function whose only param is
// typed as a project-defined interface (here, `IRestApiContext` — the
// n8n shape) must NOT be treated as a tainted-arg source by the
// interprocedural walker. Without the fix the name `context` matches
// `jsFrameworkHandlerCategory`'s Koa/Apollo single-arg shape and the
// walker fires a false SSRF finding for `context.baseUrl → fetch(...)`.
func TestJavaScriptCrossFile_TypeScript_CustomInterfaceParam_NoFinding(t *testing.T) {
	cg, paths := javascriptScanFixture(t, map[string]string{
		"types.ts": `export interface IRestApiContext {
  baseUrl: string;
  sessionId: string;
}
`,
		"api.ts": `import type { IRestApiContext } from './types';
export async function getCurrentPlan(context: IRestApiContext): Promise<unknown> {
  return await fetch(context.baseUrl + '/admin/cloud-plan');
}
`,
	})
	primeJavaScriptSigs(t, cg, paths)

	findings := WalkCrossFileTaintFlows(cg, nil)
	urlFindings := filterFindingsByRule(findings, "BATOU-INTERPROC-URL_FETCH")
	if len(urlFindings) != 0 {
		t.Errorf("custom-interface param should NOT produce URL_FETCH FP; got %d findings: %+v",
			len(urlFindings), urlFindings)
	}
}

// TestJavaScriptCrossFile_TypeScript_TypedParam covers a TS-specific
// shape: typed callee parameter + sink. Mirrors the JS path through the
// TypeScript dispatch route.
func TestJavaScriptCrossFile_TypeScript_TypedParam(t *testing.T) {
	cg, paths := javascriptScanFixture(t, map[string]string{
		"runner.ts": `export function runShell(cmd: string): void {
  const child_process = require('child_process');
  child_process.exec(cmd);
}
`,
		"app.ts": `import { runShell } from './runner';
export function handle(req: any, res: any): void {
  runShell(req.body.cmd);
}
`,
	})
	primeJavaScriptSigs(t, cg, paths)

	findings := WalkCrossFileTaintFlows(cg, nil)
	cmdFindings := filterFindingsByRule(findings, "BATOU-INTERPROC-COMMAND_EXEC")
	if len(cmdFindings) == 0 {
		t.Fatalf("expected BATOU-INTERPROC-COMMAND_EXEC via TS typed-param shape; got %d findings: %v",
			len(findings), findingRuleIDs(findings))
	}
	for _, f := range findings {
		if f.Language != "" && f.Language != rules.LangTypeScript && f.Language != rules.LangJavaScript {
			t.Errorf("finding has wrong Language %q (want LangTypeScript): %+v", f.Language, f)
		}
	}
}

// TestEnsureJavaScriptCalleeSinks_LazyPopulates checks that a JS callee
// arriving at the walker with empty SinkCalls gets them filled from the
// JS taint catalog. Mirrors TestEnsurePythonCalleeSinks_LazyPopulates.
func TestEnsureJavaScriptCalleeSinks_LazyPopulates(t *testing.T) {
	root := t.TempDir()
	runner := filepath.Join(root, "runner.js")
	if err := os.WriteFile(runner, []byte(`const child_process = require('child_process');

function run_cmd(cmd) {
  child_process.exec(cmd);
}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	node := &FuncNode{
		ID:        runner + ":run_cmd",
		FilePath:  runner,
		Name:      "run_cmd",
		Language:  rules.LangJavaScript,
		StartLine: 3,
		EndLine:   5,
	}
	if len(node.TaintSig.SinkCalls) != 0 {
		t.Fatalf("precondition: SinkCalls should be empty, got %d", len(node.TaintSig.SinkCalls))
	}

	ensureJavaScriptCalleeSinks(nil, node)

	if len(node.TaintSig.SinkCalls) == 0 {
		t.Fatalf("ensureJavaScriptCalleeSinks did not populate SinkCalls; node.TaintSig=%+v", node.TaintSig)
	}
	gotCommand := false
	for _, s := range node.TaintSig.SinkCalls {
		if s.SinkCategory == taint.SnkCommand {
			gotCommand = true
			break
		}
	}
	if !gotCommand {
		t.Errorf("expected a SnkCommand SinkRef from child_process.exec; got %+v", node.TaintSig.SinkCalls)
	}
}

// TestFindJavaScriptCallSites_BareAndMember covers the tree-sitter
// extractor for both bare-identifier and single-level member calls,
// and the assignment-bound shape (`const x = foo(...)`).
func TestFindJavaScriptCallSites_BareAndMember(t *testing.T) {
	content := `function caller() {
  const r = helper("x", req.body.q);
  mod.helper("ignored");
}
`
	caller := &FuncNode{
		Name:      "caller",
		StartLine: 1,
		EndLine:   4,
	}
	sites := findJavaScriptCallSites(content, caller, "helper", rules.LangJavaScript)
	if len(sites) != 2 {
		t.Fatalf("got %d call sites, want 2 (bare + member); sites=%+v", len(sites), sites)
	}
	// First site is `const r = helper("x", req.body.q)` — should record
	// assignedTo = "r" and 2 positional args.
	bareSite := sites[0]
	if bareSite.assignedTo != "r" {
		t.Errorf("first site assignedTo = %q, want %q", bareSite.assignedTo, "r")
	}
	if len(bareSite.args) != 2 || bareSite.args[0] != `"x"` {
		t.Errorf("first site args = %v, want [\"x\", req.body.q]", bareSite.args)
	}
	if !strings.Contains(bareSite.args[1], "req.body.q") {
		t.Errorf("first site arg[1] = %q, want to contain req.body.q", bareSite.args[1])
	}
}

// TestIsArgTaintedInJavaScriptCaller_BackwardTrace covers the
// assignment-tracing branch: the call's arg is a local variable that
// was bound to a request expression on a previous line.
func TestIsArgTaintedInJavaScriptCaller_BackwardTrace(t *testing.T) {
	body := []string{
		`function handler(req) {`,
		`  const raw = req.body.q;`,
		`  helper(raw);`,
		`}`,
	}
	if !isArgTaintedInJavaScriptCaller("raw", body, 2, &TaintSignature{}) {
		t.Errorf("expected raw to trace back to req.body.q")
	}
}

// TestIsArgTaintedInJavaScriptCaller_SanitizedAssignmentNotTainted: if
// the assignment to argVar passes through a sanitizer the arg should
// NOT be reported as tainted.
func TestIsArgTaintedInJavaScriptCaller_SanitizedAssignmentNotTainted(t *testing.T) {
	body := []string{
		`function handler(req) {`,
		`  const raw = encodeURIComponent(req.body.q);`,
		`  helper(raw);`,
		`}`,
	}
	if isArgTaintedInJavaScriptCaller("raw", body, 2, &TaintSignature{}) {
		t.Errorf("expected raw not to be tainted: wrapped in encodeURIComponent")
	}
}

// TestJSCrossFile_LiftedSink_TwoHop_Flagged exercises the canonical
// 2-hop chain that PR-Hjs's signature propagation unlocks:
//
//	db.js      :: function run(cmd) { child_process.exec(cmd); }
//	service.js :: function helper(x) { run(x); }   // pure forwarder
//	app.js     :: function handle(req, res) { helper(req.body.cmd); }
//
// PR-Gjs alone catches `helper -> run` and `handle -> helper` only when
// helper has a direct sink; here helper is a pure forwarder so the lift
// (PR-Hjs) is what enables the cross-file walker to fire on
// `handle -> helper`. The emitted finding's sink step must point at
// db.js (the leaf where child_process.exec actually lives), preserved
// via OriginFile/OriginLine plumbing.
func TestJSCrossFile_LiftedSink_TwoHop_Flagged(t *testing.T) {
	cg, paths := javascriptScanFixture(t, map[string]string{
		"db.js": `const child_process = require('child_process');
function run(cmd) {
  child_process.exec(cmd);
}
module.exports = { run };
`,
		"service.js": `const { run } = require('./db');
function helper(x) {
  run(x);
}
module.exports = { helper };
`,
		"app.js": `const { helper } = require('./service');
function handle(req, res) {
  helper(req.body.cmd);
}
module.exports = { handle };
`,
	})
	primeJavaScriptSigs(t, cg, paths)

	propStats := PropagateSignaturesAcrossCallgraph(cg, nil)
	if propStats.SinksLifted == 0 {
		t.Fatalf("expected sig propagation to lift at least one JS sink; got %+v", propStats)
	}

	findings := WalkCrossFileTaintFlows(cg, nil)
	cmdFindings := filterFindingsByRule(findings, "BATOU-INTERPROC-COMMAND_EXEC")
	if len(cmdFindings) == 0 {
		t.Fatalf("expected BATOU-INTERPROC-COMMAND_EXEC via 2-hop JS chain; got %d findings: %v",
			len(findings), findingRuleIDs(findings))
	}
	// At least one finding must point at the deep sink in db.js.
	sinkSeen := false
	for _, f := range cmdFindings {
		for _, st := range f.TaintPath {
			if st.Kind == rules.TaintStepSink && st.File == paths["db.js"] {
				sinkSeen = true
				break
			}
		}
	}
	if !sinkSeen {
		t.Errorf("no finding had a sink step in db.js (the leaf); cmdFindings=%+v", cmdFindings)
	}
}

// TestJSCrossFile_LiftedSink_ThreeHop_Flagged extends the 2-hop test
// one level deeper: handler -> service -> repo -> sink. Every
// intermediate node passes its own first parameter to the next call,
// so PR-Hjs's signature propagation should converge by lifting the
// child_process.exec sink through repo then through service, and the
// cross-file walker should emit a BATOU-INTERPROC-COMMAND_EXEC finding
// at the handle -> service call site whose TaintPath reaches all the
// way down to db.js.
func TestJSCrossFile_LiftedSink_ThreeHop_Flagged(t *testing.T) {
	cg, paths := javascriptScanFixture(t, map[string]string{
		"db.js": `const child_process = require('child_process');
function run(cmd) {
  child_process.exec(cmd);
}
module.exports = { run };
`,
		"repo.js": `const { run } = require('./db');
function repoCall(y) {
  run(y);
}
module.exports = { repoCall };
`,
		"service.js": `const { repoCall } = require('./repo');
function service(z) {
  repoCall(z);
}
module.exports = { service };
`,
		"app.js": `const { service } = require('./service');
function handle(req, res) {
  service(req.body.cmd);
}
module.exports = { handle };
`,
	})
	primeJavaScriptSigs(t, cg, paths)

	propStats := PropagateSignaturesAcrossCallgraph(cg, nil)
	// Two distinct lifts: run -> repoCall, then repoCall -> service.
	// (handle's req.body.cmd is a direct source expression so the walker
	// fires Path A directly once service has the lifted sink.)
	if propStats.SinksLifted < 2 {
		t.Fatalf("expected sig propagation to lift >= 2 JS sinks (run->repoCall, repoCall->service); got %+v",
			propStats)
	}

	findings := WalkCrossFileTaintFlows(cg, nil)
	cmdFindings := filterFindingsByRule(findings, "BATOU-INTERPROC-COMMAND_EXEC")
	if len(cmdFindings) == 0 {
		t.Fatalf("expected at least one BATOU-INTERPROC-COMMAND_EXEC finding through 3-hop JS chain; got %d findings: %v",
			len(findings), findingRuleIDs(findings))
	}
	// Some finding must point at the actual child_process.exec sink in
	// db.js — OriginFile carry-through is what guarantees the leaf is
	// preserved through the chain.
	sinkSeen := false
	for _, f := range cmdFindings {
		for _, st := range f.TaintPath {
			if st.Kind == rules.TaintStepSink && st.File == paths["db.js"] {
				sinkSeen = true
				break
			}
		}
	}
	if !sinkSeen {
		t.Errorf("no finding's sink step pointed at db.js through the 3-hop chain; findings=%+v", cmdFindings)
	}
}

// TestJSCrossFile_LiftedSink_SanitizedAtIntermediate_NotFlagged asserts
// that wrapping the param through a sanitizer at the intermediate hop
// suppresses the lift's downstream finding. Service.js calls
// encodeURIComponent on the param before forwarding to repo.run — the
// repo.run sink should not lift up to service because the arg expression
// no longer matches the caller's bare param name.
func TestJSCrossFile_LiftedSink_SanitizedAtIntermediate_NotFlagged(t *testing.T) {
	cg, paths := javascriptScanFixture(t, map[string]string{
		"db.js": `const child_process = require('child_process');
function run(cmd) {
  child_process.exec(cmd);
}
module.exports = { run };
`,
		"service.js": `const { run } = require('./db');
function helper(x) {
  const safe = encodeURIComponent(x);
  run(safe);
}
module.exports = { helper };
`,
		"app.js": `const { helper } = require('./service');
function handle(req, res) {
  helper(req.body.cmd);
}
module.exports = { handle };
`,
	})
	primeJavaScriptSigs(t, cg, paths)

	_ = PropagateSignaturesAcrossCallgraph(cg, nil)
	findings := WalkCrossFileTaintFlows(cg, nil)
	cmdFindings := filterFindingsByRule(findings, "BATOU-INTERPROC-COMMAND_EXEC")
	// service.helper(req.body.cmd) -> repo.run lift does NOT happen
	// because helper passes `safe` (not its bare param `x`) to run. So
	// helper has no inherited sink and the handle -> helper call is not
	// flagged. The leaf db.js -> run sink may still produce a separate
	// finding for service.helper -> run, but only because helper passes
	// `safe` not `x` — and our propagation matches param names exactly,
	// so the lift is correctly suppressed.
	for _, f := range cmdFindings {
		// Confirm no finding fires at app.js -> helper. (Sanitized
		// intermediate suppresses the lifted-sink path.)
		if f.FilePath == paths["app.js"] {
			t.Errorf("sanitized intermediate hop should suppress the app.js -> helper finding; got %+v", f)
		}
	}
}

// TestJSCrossFile_LiftedSink_TaintPath_ContainsAllHops verifies that the
// emitted finding's TaintPath spans every hop of a 2-hop chain: the
// caller's source arg, the propagation "forwarded by ..." step at the
// inheriting function, and the leaf-sink step pointing at the deepest
// file/line.
func TestJSCrossFile_LiftedSink_TaintPath_ContainsAllHops(t *testing.T) {
	cg, paths := javascriptScanFixture(t, map[string]string{
		"db.js": `const child_process = require('child_process');
function run(cmd) {
  child_process.exec(cmd);
}
module.exports = { run };
`,
		"service.js": `const { run } = require('./db');
function helper(x) {
  run(x);
}
module.exports = { helper };
`,
		"app.js": `const { helper } = require('./service');
function handle(req, res) {
  helper(req.body.cmd);
}
module.exports = { handle };
`,
	})
	primeJavaScriptSigs(t, cg, paths)

	_ = PropagateSignaturesAcrossCallgraph(cg, nil)
	findings := WalkCrossFileTaintFlows(cg, nil)
	cmdFindings := filterFindingsByRule(findings, "BATOU-INTERPROC-COMMAND_EXEC")
	if len(cmdFindings) == 0 {
		t.Fatalf("expected BATOU-INTERPROC-COMMAND_EXEC; got 0 findings (all: %v)", findingRuleIDs(findings))
	}

	// Find at least one finding whose TaintPath has:
	//   - a source step (the caller's tainted arg)
	//   - a propagation step labeled with "inherited sink" or "(via ...)"
	//   - a sink step in db.js (the leaf)
	pathOk := false
	for _, f := range cmdFindings {
		hasSource, hasInheritedProp, hasLeafSink := false, false, false
		for _, st := range f.TaintPath {
			switch {
			case st.Kind == rules.TaintStepSource:
				hasSource = true
			case st.Kind == rules.TaintStepPropagation &&
				strings.Contains(st.Label, "inherited sink"):
				hasInheritedProp = true
			case st.Kind == rules.TaintStepSink && st.File == paths["db.js"]:
				hasLeafSink = true
			}
		}
		if hasSource && hasInheritedProp && hasLeafSink {
			pathOk = true
			break
		}
	}
	if !pathOk {
		t.Errorf("no finding's TaintPath contained all expected hops (source + inherited-sink propagation + leaf sink in db.js); findings=%+v", cmdFindings)
	}
}

// TestJavaScriptCrossFile_TaintedReturn_AutoSeed_CommandExec is the
// producer-half regression proof, mirroring TestLuaCrossFile_Tainted-
// Return_ViaVariable: a required module exposes a getter that returns
// request-controlled data (`return req.query.name`), and the importer
// stores the return value then forwards it to child_process.exec(). The
// TaintedReturns map is seeded AUTOMATICALLY by ensureJavaScriptCallee-
// Returns — no planted test data. Expected: one BATOU-INTERPROC-
// COMMAND_EXEC (CWE-78) whose multi-step cross-file taint_path has a
// source step in a.js and a sink step in b.js.
func TestJavaScriptCrossFile_TaintedReturn_AutoSeed_CommandExec(t *testing.T) {
	cg, paths := javascriptScanFixture(t, map[string]string{
		"a.js": `function getName(req) {
  return req.query.name;
}
module.exports = { getName };
`,
		"b.js": `const { getName } = require('./a');
const cp = require('child_process');
function handler(req, res) {
  const n = getName(req);
  cp.exec(n);
}
module.exports = { handler };
`,
	})
	primeJavaScriptSigs(t, cg, paths)

	findings := WalkCrossFileTaintFlows(cg, nil)
	cmdFindings := filterFindingsByRule(findings, "BATOU-INTERPROC-COMMAND_EXEC")
	if len(cmdFindings) == 0 {
		t.Fatalf("expected BATOU-INTERPROC-COMMAND_EXEC via auto-seeded tainted return; got %d findings: %v",
			len(findings), findingRuleIDs(findings))
	}
	// The flow must cross files: a source step in a.js (the getter) and a
	// sink step in b.js (the exec call), and at least 3 path steps.
	srcInA, sinkInB := false, false
	for _, f := range cmdFindings {
		if f.CWEID != "CWE-78" {
			t.Errorf("expected CWE-78, got %q", f.CWEID)
		}
		if f.Language != rules.LangJavaScript && f.Language != rules.LangTypeScript {
			t.Errorf("expected Language js/ts, got %q", f.Language)
		}
		if len(f.TaintPath) < 3 {
			t.Errorf("expected a multi-step (>=3) cross-file taint_path; got %d steps: %+v",
				len(f.TaintPath), f.TaintPath)
		}
		for _, st := range f.TaintPath {
			if st.Kind == rules.TaintStepSource && st.File == paths["a.js"] {
				srcInA = true
			}
			if st.Kind == rules.TaintStepSink && st.File == paths["b.js"] {
				sinkInB = true
			}
		}
	}
	if !srcInA {
		t.Errorf("no COMMAND_EXEC finding had a source step in a.js; findings=%+v", cmdFindings)
	}
	if !sinkInB {
		t.Errorf("no COMMAND_EXEC finding had a sink step in b.js; findings=%+v", cmdFindings)
	}
}

// TestJavaScriptCrossFile_TaintedReturn_SanitizedReturn_NoFinding is the
// negative control for the producer: the getter escapes the request data
// before returning it (`return escape(req.body.x)`), so ensureJavaScript-
// CalleeReturns must NOT seed TaintedReturns and no cross-file finding
// should be produced. Mirrors TestLuaCrossFile_Sanitized_NoFinding.
func TestJavaScriptCrossFile_TaintedReturn_SanitizedReturn_NoFinding(t *testing.T) {
	cg, paths := javascriptScanFixture(t, map[string]string{
		"a.js": `function getName(req) {
  return escape(req.body.x);
}
module.exports = { getName };
`,
		"b.js": `const { getName } = require('./a');
const cp = require('child_process');
function handler(req, res) {
  const n = getName(req);
  cp.exec(n);
}
module.exports = { handler };
`,
	})
	primeJavaScriptSigs(t, cg, paths)

	findings := WalkCrossFileTaintFlows(cg, nil)
	cmdFindings := filterFindingsByRule(findings, "BATOU-INTERPROC-COMMAND_EXEC")
	if len(cmdFindings) != 0 {
		t.Fatalf("sanitized return should not produce a COMMAND_EXEC finding; got %d: %+v",
			len(cmdFindings), cmdFindings)
	}
	// Sanity: the source step (a.js) is never reached because the seed is
	// suppressed — guard against accidental over-fire.
	for _, f := range cmdFindings {
		for _, st := range f.TaintPath {
			if st.File == paths["a.js"] {
				t.Errorf("unexpected taint step referencing a.js when return is sanitized: %+v", f)
			}
		}
	}
}

// --- PR3: access-path field-sensitivity precision tests ------------------
//
// These four tests pin the headline precision behaviour: a field-level
// cross-file flow fires only when the EXACT field the sink reads is the
// one carrying taint, and stays silent when a sibling field is the
// tainted one. They are the committed analog of the binary precision
// probe.

// TestJavaScriptCrossFile_FieldSensitive_Fire is the FIRE half: the helper
// sinks `o.cmd`, and the caller taints exactly `o.cmd` with
// `o.cmd = req.body.cmd`. Expected: BATOU-INTERPROC-COMMAND_EXEC.
func TestJavaScriptCrossFile_FieldSensitive_Fire(t *testing.T) {
	cg, paths := javascriptScanFixture(t, map[string]string{
		"a.js": `const cp = require('child_process');
function run(o) {
  cp.exec(o.cmd);
}
module.exports = { run };
`,
		"b.js": `const { run } = require('./a');
function handle(req, res) {
  const o = {};
  o.cmd = req.body.cmd;
  run(o);
}
module.exports = { handle };
`,
	})
	primeJavaScriptSigs(t, cg, paths)

	findings := WalkCrossFileTaintFlows(cg, nil)
	cmd := filterFindingsByRule(findings, "BATOU-INTERPROC-COMMAND_EXEC")
	if len(cmd) == 0 {
		t.Fatalf("expected BATOU-INTERPROC-COMMAND_EXEC when the sunk field o.cmd is the tainted field; got %d: %v",
			len(findings), findingRuleIDs(findings))
	}
}

// TestJavaScriptCrossFile_FieldSensitive_SiblingSilent is the SILENT half:
// the helper sinks `o.cmd`, but the caller assigns `o.cmd = "ls"` (a
// literal) and taints only the SIBLING `o.other = req.body.cmd`. The sink
// reads the literal field, so NO finding must fire — the precision gain.
func TestJavaScriptCrossFile_FieldSensitive_SiblingSilent(t *testing.T) {
	cg, paths := javascriptScanFixture(t, map[string]string{
		"a.js": `const cp = require('child_process');
function run(o) {
  cp.exec(o.cmd);
}
module.exports = { run };
`,
		"b.js": `const { run } = require('./a');
function handle(req, res) {
  const o = {};
  o.cmd = "ls";
  o.other = req.body.cmd;
  run(o);
}
module.exports = { handle };
`,
	})
	primeJavaScriptSigs(t, cg, paths)

	findings := WalkCrossFileTaintFlows(cg, nil)
	cmd := filterFindingsByRule(findings, "BATOU-INTERPROC-COMMAND_EXEC")
	if len(cmd) != 0 {
		t.Fatalf("expected NO finding: sink reads o.cmd which is the literal \"ls\"; only sibling o.other is tainted; got %d: %+v",
			len(cmd), cmd)
	}
}

// TestJavaScriptCrossFile_ReturnPath_Fire is the return-composition FIRE
// half: the callee returns `{user:{id:req.query.id}, name:"x"}` and the
// caller sinks `r.user.id` — the tainted return path. Expected:
// BATOU-INTERPROC-CODE_EVAL.
func TestJavaScriptCrossFile_ReturnPath_Fire(t *testing.T) {
	cg, paths := javascriptScanFixture(t, map[string]string{
		"get.js": `function getData(req) {
  return { user: { id: req.query.id }, name: "safe" };
}
module.exports = { getData };
`,
		"app.js": `const { getData } = require('./get');
function handle(req, res) {
  const r = getData(req);
  eval(r.user.id);
}
module.exports = { handle };
`,
	})
	primeJavaScriptSigs(t, cg, paths)

	findings := WalkCrossFileTaintFlows(cg, nil)
	ev := filterFindingsByRule(findings, "BATOU-INTERPROC-CODE_EVAL")
	if len(ev) == 0 {
		t.Fatalf("expected BATOU-INTERPROC-CODE_EVAL when sinking the tainted return field r.user.id; got %d: %v",
			len(findings), findingRuleIDs(findings))
	}
}

// TestJavaScriptCrossFile_ReturnPath_SiblingSilent is the return-composition
// SILENT half: same callee, but the caller sinks `r.name` — a non-tainted
// return field. No finding must fire.
func TestJavaScriptCrossFile_ReturnPath_SiblingSilent(t *testing.T) {
	cg, paths := javascriptScanFixture(t, map[string]string{
		"get.js": `function getData(req) {
  return { user: { id: req.query.id }, name: "safe" };
}
module.exports = { getData };
`,
		"app.js": `const { getData } = require('./get');
function handle(req, res) {
  const r = getData(req);
  eval(r.name);
}
module.exports = { handle };
`,
	})
	primeJavaScriptSigs(t, cg, paths)

	findings := WalkCrossFileTaintFlows(cg, nil)
	ev := filterFindingsByRule(findings, "BATOU-INTERPROC-CODE_EVAL")
	if len(ev) != 0 {
		t.Fatalf("expected NO finding: r.name is not a tainted return field (only user.id is); got %d: %+v",
			len(ev), ev)
	}
}

// --- #31: multi-hop tainted-RETURN composition ----------------------------
//
// These tests pin the headline of issue #31: the cross-file fixpoint must
// compose tainted RETURNS transitively, not just sinks. A relay that does
// `return getA(req)` carries getA's tainted return up to its own caller, so
// a 2- (and 3-) hop return chain reaches a downstream sink. Without
// appendInheritedReturn the relay's TaintedReturns stays nil and taint is
// dropped at the first relay.

// TestJSCrossFile_LiftedReturn_TwoHop_Flagged is the headline milestone:
// a.js getA returns req.query.x; b.js relay does `return getA(req)`; c.js
// handle stores `const n = relay(req)` and sinks `cp.exec(n)`. The
// return-lift must propagate getA's tainted return up to relay so the
// walker fires COMMAND_EXEC at the relay->handle return chain.
func TestJSCrossFile_LiftedReturn_TwoHop_Flagged(t *testing.T) {
	cg, paths := javascriptScanFixture(t, map[string]string{
		"a.js": `function getA(req) {
  return req.query.x;
}
module.exports = { getA };
`,
		"b.js": `const { getA } = require('./a');
function relay(req) {
  return getA(req);
}
module.exports = { relay };
`,
		"c.js": `const cp = require('child_process');
const { relay } = require('./b');
function handle(req) {
  const n = relay(req);
  cp.exec(n);
}
module.exports = { handle };
`,
	})
	primeJavaScriptSigs(t, cg, paths)

	// The fixpoint must lift getA's tainted return into relay. Before this
	// pass relay.TaintedReturns is nil (the single-body producer only
	// recognises `return <source>`, not `return getA(...)`).
	PropagateSignaturesAcrossCallgraph(cg, nil)
	relayTainted := false
	for _, n := range cg.Nodes {
		if n.Name == "relay" && len(n.TaintSig.TaintedReturns) > 0 {
			relayTainted = true
		}
	}
	if !relayTainted {
		t.Fatalf("expected return-lift to populate relay.TaintedReturns via #31 fixpoint")
	}

	findings := WalkCrossFileTaintFlows(cg, nil)
	cmd := filterFindingsByRule(findings, "BATOU-INTERPROC-COMMAND_EXEC")
	if len(cmd) == 0 {
		t.Fatalf("expected BATOU-INTERPROC-COMMAND_EXEC via 2-hop return chain; got %d findings: %v",
			len(findings), findingRuleIDs(findings))
	}
	// The flow must reach the cp.exec sink in c.js.
	sinkInC := false
	for _, f := range cmd {
		for _, st := range f.TaintPath {
			if st.Kind == rules.TaintStepSink && st.File == paths["c.js"] {
				sinkInC = true
			}
		}
	}
	if !sinkInC {
		t.Errorf("no COMMAND_EXEC finding sink-stepped in c.js; findings=%+v", cmd)
	}
}

// TestJSCrossFile_LiftedReturn_ThreeHop_Flagged extends the chain one hop:
// getA -> relay1 -> relay2 (each `return <next>(req)`) -> handle sinks the
// result. The fixpoint must compose the tainted return across both relays.
func TestJSCrossFile_LiftedReturn_ThreeHop_Flagged(t *testing.T) {
	cg, paths := javascriptScanFixture(t, map[string]string{
		"a.js": `function getA(req) {
  return req.query.x;
}
module.exports = { getA };
`,
		"b.js": `const { getA } = require('./a');
function relay1(req) {
  return getA(req);
}
module.exports = { relay1 };
`,
		"c.js": `const { relay1 } = require('./b');
function relay2(req) {
  return relay1(req);
}
module.exports = { relay2 };
`,
		"d.js": `const cp = require('child_process');
const { relay2 } = require('./c');
function handle(req) {
  const n = relay2(req);
  cp.exec(n);
}
module.exports = { handle };
`,
	})
	primeJavaScriptSigs(t, cg, paths)

	PropagateSignaturesAcrossCallgraph(cg, nil)
	// Both relays must end up with a tainted return.
	relay1Tainted, relay2Tainted := false, false
	for _, n := range cg.Nodes {
		if n.Name == "relay1" && len(n.TaintSig.TaintedReturns) > 0 {
			relay1Tainted = true
		}
		if n.Name == "relay2" && len(n.TaintSig.TaintedReturns) > 0 {
			relay2Tainted = true
		}
	}
	if !relay1Tainted || !relay2Tainted {
		t.Fatalf("expected return-lift to populate relay1 (%v) AND relay2 (%v) across 3 hops",
			relay1Tainted, relay2Tainted)
	}

	findings := WalkCrossFileTaintFlows(cg, nil)
	cmd := filterFindingsByRule(findings, "BATOU-INTERPROC-COMMAND_EXEC")
	if len(cmd) == 0 {
		t.Fatalf("expected BATOU-INTERPROC-COMMAND_EXEC via 3-hop return chain; got %d findings: %v",
			len(findings), findingRuleIDs(findings))
	}
}

// TestJSCrossFile_InlineReturn_OneHop_Flagged is PR-1: the callee's tainted
// return is consumed directly inside a sink argument on the call line —
// `cp.exec(getA(req))` — with no intervening variable. The relaxed
// checkJavaScriptCallerUsesTaintedReturn must fire here.
func TestJSCrossFile_InlineReturn_OneHop_Flagged(t *testing.T) {
	cg, paths := javascriptScanFixture(t, map[string]string{
		"a.js": `function getA(req) {
  return req.query.x;
}
module.exports = { getA };
`,
		"c.js": `const cp = require('child_process');
const { getA } = require('./a');
function handle(req) {
  cp.exec(getA(req));
}
module.exports = { handle };
`,
	})
	primeJavaScriptSigs(t, cg, paths)

	findings := WalkCrossFileTaintFlows(cg, nil)
	cmd := filterFindingsByRule(findings, "BATOU-INTERPROC-COMMAND_EXEC")
	if len(cmd) == 0 {
		t.Fatalf("expected BATOU-INTERPROC-COMMAND_EXEC via inline 1-hop `cp.exec(getA(req))`; got %d findings: %v",
			len(findings), findingRuleIDs(findings))
	}
	srcInA, sinkInC := false, false
	for _, f := range cmd {
		for _, st := range f.TaintPath {
			if st.Kind == rules.TaintStepSource && st.File == paths["a.js"] {
				srcInA = true
			}
			if st.Kind == rules.TaintStepSink && st.File == paths["c.js"] {
				sinkInC = true
			}
		}
	}
	if !srcInA || !sinkInC {
		t.Errorf("inline finding must trace a.js source -> c.js sink; srcInA=%v sinkInC=%v findings=%+v",
			srcInA, sinkInC, cmd)
	}
}

// TestJSCrossFile_LiftedReturn_SanitizedRelay_NoFinding is the negative
// control: the relay sanitizes the value before returning it
// (`return escape(getA(req))`), so the lift must NOT carry taint up and no
// downstream finding may fire. Guards the FPR-flat gate for #31.
func TestJSCrossFile_LiftedReturn_SanitizedRelay_NoFinding(t *testing.T) {
	cg, paths := javascriptScanFixture(t, map[string]string{
		"a.js": `function getA(req) {
  return req.query.x;
}
module.exports = { getA };
`,
		"b.js": `const { getA } = require('./a');
function relay(req) {
  return escape(getA(req));
}
module.exports = { relay };
`,
		"c.js": `const cp = require('child_process');
const { relay } = require('./b');
function handle(req) {
  const n = relay(req);
  cp.exec(n);
}
module.exports = { handle };
`,
	})
	primeJavaScriptSigs(t, cg, paths)

	PropagateSignaturesAcrossCallgraph(cg, nil)
	findings := WalkCrossFileTaintFlows(cg, nil)
	cmd := filterFindingsByRule(findings, "BATOU-INTERPROC-COMMAND_EXEC")
	if len(cmd) != 0 {
		t.Fatalf("sanitized relay return must not produce a COMMAND_EXEC finding; got %d: %+v",
			len(cmd), cmd)
	}
}
