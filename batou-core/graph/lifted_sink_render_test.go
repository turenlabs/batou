// PR-Ipy: lifted-sink matched_text rendering tests.
//
// PR-Hpy added SinkRef.OriginFile / SinkRef.OriginLine so the leaf-sink
// location survives multi-hop sig propagation. Before PR-Ipy the
// cross-file walkers' matched_text rendering used (matchedSink.Method,
// matchedSink.Line) directly — which for lifted sinks points at the
// "(via X)" hop in the inheriting function, NOT the actual dangerous
// call. The Django form.user case rendered as "-> [] (line 388)" where
// 388 was the wrapper's call line in admin.py and the leaf
// session-flush in middleware.py was lost.
//
// These tests pin the formatSinkLocation helper + its callers in both
// the Go and Python walkers so future refactors can't silently regress
// the leaf-sink rendering.
package graph

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// TestFormatSinkLocation_LiftedSinkUsesOrigin pins the helper that
// powers the matched_text fix: when SinkRef.OriginFile is set the
// renderer must surface OriginFile:OriginLine, not the via-hop line.
func TestFormatSinkLocation_LiftedSinkUsesOrigin(t *testing.T) {
	sink := SinkRef{
		SinkCategory: taint.SnkTrustBoundary,
		MethodName:   "[] (via update_session_auth_hash)",
		Line:         388, // via-hop line in admin.py
		ArgFromParam: 0,
		OriginFile:   "/repo/django/contrib/auth/middleware.py",
		OriginLine:   50,
	}
	// Lifted sinks ignore the calleeFile fallback — OriginFile wins.
	got := formatSinkLocation(sink, "/repo/django/contrib/auth/__init__.py")
	want := "(in /repo/django/contrib/auth/middleware.py:50)"
	if got != want {
		t.Errorf("formatSinkLocation(lifted) = %q, want %q", got, want)
	}
}

// TestFormatSinkLocation_DirectSinkUsesCalleeFile pins the direct-sink
// path: SinkRefs with OriginFile == "" surface the callee's file path
// via the calleeFile fallback so cross-file findings make clear which
// file the dangerous call lives in. This is what fixed the Django
// `update_session_auth_hash() -> [] (line 388)` case — line 388 is in
// the callee's __init__.py, NOT in admin.py where the finding is
// reported.
func TestFormatSinkLocation_DirectSinkUsesCalleeFile(t *testing.T) {
	sink := SinkRef{
		SinkCategory: taint.SnkSQLQuery,
		MethodName:   "db.Query",
		Line:         42,
		ArgFromParam: 0,
		// OriginFile deliberately empty — direct sink in the callee.
	}
	got := formatSinkLocation(sink, "/repo/pkg/db.go")
	want := "(in /repo/pkg/db.go:42)"
	if got != want {
		t.Errorf("formatSinkLocation(direct) = %q, want %q", got, want)
	}
}

// TestFormatSinkLocation_LegacyFallback pins the no-context degraded
// rendering: when neither OriginFile nor calleeFile is provided the
// helper falls back to the legacy "(line N)" form so it remains usable
// in unit tests or any caller that doesn't have a callee context.
func TestFormatSinkLocation_LegacyFallback(t *testing.T) {
	sink := SinkRef{MethodName: "exec", Line: 7}
	got := formatSinkLocation(sink, "")
	want := "(line 7)"
	if got != want {
		t.Errorf("formatSinkLocation(no-context) = %q, want %q", got, want)
	}
}

// TestPythonCrossFile_LiftedSinkRendersLeafLocation is the integration
// regression test for the Django finding. It builds a 3-hop chain so
// PropagateSignaturesAcrossCallgraph lifts the leaf sink twice; the
// emitted matched_text must mention the leaf file (runners.py) and
// NOT contain the "(line N)" fallback used by direct sinks. The
// TaintPath's last (sink) step must also point at the leaf file.
func TestPythonCrossFile_LiftedSinkRendersLeafLocation(t *testing.T) {
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
    forward(request.args.get('q'))
`,
	})

	primePythonSigs(t, cg, paths)
	if stats := PropagateSignaturesAcrossCallgraph(cg, nil); stats.SinksLifted == 0 {
		t.Fatalf("expected propagation to lift at least one sink for the 2-hop chain; stats=%+v", stats)
	}

	findings := WalkCrossFileTaintFlows(cg, nil)
	cmdFindings := filterFindingsByRule(findings, "BATOU-INTERPROC-COMMAND_EXEC")
	if len(cmdFindings) == 0 {
		t.Fatalf("expected at least one BATOU-INTERPROC-COMMAND_EXEC finding; got %d (%v)",
			len(findings), findingRuleIDs(findings))
	}

	// At least one finding must render the leaf-sink location instead
	// of the via-hop "(line N)". We can't pin a specific line number
	// (it depends on the fixture text), but the matched_text must
	// reference runners.py — the leaf file — via the "(in ...)" form.
	runnersPath := paths["runners.py"]
	helpersPath := paths["helpers.py"]
	var leafRendered, sinkStepOnLeaf bool
	var sawMatched string
	for _, f := range cmdFindings {
		sawMatched = f.MatchedText
		if strings.Contains(f.MatchedText, "(in "+runnersPath+":") {
			leafRendered = true
		}
		// Direct (non-lifted) sinks would render "(line N)" with the
		// callee being helpers.py's forward — but here the chain lifts
		// runners.run_cmd's subprocess.run sink up through helpers.forward
		// onto app.handle. The matched_text for the handle→forward edge
		// MUST surface the leaf "(in runners.py:...)" form. Pin both:
		// the leaf rendering succeeded AND the via-hop file is NOT used
		// as the location for the lifted finding.
		if strings.Contains(f.MatchedText, "(in "+helpersPath+":") {
			t.Errorf("matched_text for lifted finding points at via-hop helpers.py, want leaf runners.py: %q",
				f.MatchedText)
		}
		// TaintPath's last sink step on a lifted finding lives in the
		// leaf file.
		for i := len(f.TaintPath) - 1; i >= 0; i-- {
			step := f.TaintPath[i]
			if step.Kind != rules.TaintStepSink {
				continue
			}
			if step.File == runnersPath {
				sinkStepOnLeaf = true
			}
			break
		}
	}
	if !leafRendered {
		t.Errorf("no finding's matched_text rendered the leaf-sink location \"(in %s:N)\"; last matched_text=%q",
			runnersPath, sawMatched)
	}
	if !sinkStepOnLeaf {
		t.Errorf("no finding's TaintPath ended on a sink step in the leaf file %s; findings=%+v",
			runnersPath, cmdFindings)
	}
}

// TestPythonCrossFile_DirectSinkRendersCalleeFile pins the direct-sink
// (1-hop) rendering: the matched_text must surface the callee's file
// path via "(in <file>:<line>)" so cross-file findings make clear
// which file the sink lives in. This is the Django form.user case:
// `update_session_auth_hash()` lives in __init__.py but the finding is
// reported at the caller in admin.py, so line numbers alone were
// ambiguous before PR-Ipy.
func TestPythonCrossFile_DirectSinkRendersCalleeFile(t *testing.T) {
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
	// No lifts on a 1-hop chain — the sink already lives in find_user.
	findings := WalkCrossFileTaintFlows(cg, nil)
	sqlFindings := filterFindingsByRule(findings, "BATOU-INTERPROC-SQL_QUERY")
	if len(sqlFindings) == 0 {
		t.Fatalf("expected BATOU-INTERPROC-SQL_QUERY finding; got %v", findingRuleIDs(findings))
	}

	dbPath := paths["db.py"]
	for _, f := range sqlFindings {
		// Direct cross-file sink: surface the callee's file so the
		// finding makes clear where the dangerous call lives.
		want := "(in " + dbPath + ":"
		if !strings.Contains(f.MatchedText, want) {
			t.Errorf("direct cross-file sink should render %q; got matched_text=%q",
				want, f.MatchedText)
		}
		// The TaintPath's sink step lives in db.py (the callee).
		var sinkStep *rules.TaintStep
		for i := len(f.TaintPath) - 1; i >= 0; i-- {
			if f.TaintPath[i].Kind == rules.TaintStepSink {
				sinkStep = &f.TaintPath[i]
				break
			}
		}
		if sinkStep == nil || sinkStep.File != dbPath {
			t.Errorf("direct sink's TaintPath last sink step should be in %s; got %+v",
				dbPath, sinkStep)
		}
	}
}

// TestFormatSinkLocation_MultiHopOriginPreserved exercises the
// "callee inherits a lifted sink which itself was lifted" path: the
// final SinkRef on the top-level caller should still carry the leaf
// OriginFile/OriginLine (set on the first lift, never overwritten).
// This pins the OriginFile carry-through that appendInheritedSink
// is supposed to guarantee.
func TestFormatSinkLocation_MultiHopOriginPreserved(t *testing.T) {
	root := t.TempDir()
	if err := writeFiles(t, root, map[string]string{
		"runners.py":    "def run(c):\n    subprocess.run(c, shell=True)\n",
		"helpers.py":    "from runners import run\n\ndef forward(x):\n    run(x)\n",
		"middleware.py": "from helpers import forward\n\ndef middleware(y):\n    forward(y)\n",
	}); err != nil {
		t.Fatal(err)
	}
	leafFile := filepath.Join(root, "runners.py")
	helpersFile := filepath.Join(root, "helpers.py")
	middlewareFile := filepath.Join(root, "middleware.py")

	cg := NewCallGraph(root, "test")
	cg.AddNode(&FuncNode{
		ID: leafFile + ":run", FilePath: leafFile, Name: "run", Language: rules.LangPython,
		StartLine: 1, EndLine: 2,
		TaintSig: TaintSignature{
			Params:    []ParamTaint{{Index: 0, Name: "c"}},
			SinkCalls: []SinkRef{{SinkCategory: taint.SnkCommand, MethodName: "subprocess.run", Line: 2, ArgFromParam: 0}},
		},
	})
	cg.AddNode(&FuncNode{
		ID: helpersFile + ":forward", FilePath: helpersFile, Name: "forward", Language: rules.LangPython,
		StartLine: 3, EndLine: 4, Calls: []string{leafFile + ":run"},
		TaintSig: TaintSignature{Params: []ParamTaint{{Index: 0, Name: "x"}}},
	})
	cg.AddNode(&FuncNode{
		ID: middlewareFile + ":middleware", FilePath: middlewareFile, Name: "middleware",
		Language: rules.LangPython, StartLine: 3, EndLine: 4, Calls: []string{helpersFile + ":forward"},
		TaintSig: TaintSignature{Params: []ParamTaint{{Index: 0, Name: "y"}}},
	})

	stats := PropagateSignaturesAcrossCallgraph(cg, nil)
	if stats.SinksLifted < 2 {
		t.Fatalf("expected at least 2 lifts (run->forward, forward->middleware); stats=%+v", stats)
	}

	// After 2 lifts, middleware's SinkCalls should carry OriginFile =
	// runners.py (the leaf), NOT helpers.py (the intermediate hop).
	mid := cg.GetNode(middlewareFile + ":middleware")
	if len(mid.TaintSig.SinkCalls) == 0 {
		t.Fatalf("middleware did not inherit any sinks after propagation; sig=%+v", mid.TaintSig)
	}
	got := mid.TaintSig.SinkCalls[0]
	if got.OriginFile != leafFile {
		t.Errorf("middleware sink OriginFile = %q, want leaf %q (origin was overwritten by intermediate hop)",
			got.OriginFile, leafFile)
	}
	if got.OriginLine != 2 {
		t.Errorf("middleware sink OriginLine = %d, want 2", got.OriginLine)
	}

	// formatSinkLocation on the multi-hop SinkRef must point at the
	// leaf, not the intermediate hop — pass the intermediate hop as
	// calleeFile to prove the lifted OriginFile overrides the fallback.
	rendered := formatSinkLocation(got, helpersFile)
	if !strings.Contains(rendered, leafFile) {
		t.Errorf("formatSinkLocation rendered %q, want it to reference leaf %s", rendered, leafFile)
	}
	if strings.Contains(rendered, helpersFile) {
		t.Errorf("formatSinkLocation rendered %q, want it NOT to mention intermediate hop %s",
			rendered, helpersFile)
	}
}
