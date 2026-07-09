// Cross-file Python interproc walker tests for the NO-MANIFEST case.
//
// Regression coverage for the silent-failure fix in resolver_python.go's
// ProjectRoot Pass 3. Before the fix, a Python project with NO
// pyproject.toml / setup.py / setup.cfg / __init__.py yielded ZERO
// cross-file flows with no signal: source-in-file-A -> sink-in-file-B was
// silently dropped. The root cause was an off-by-one in the ModuleRoot
// anchor — Pass 3 returned the scanned directory itself as the synthetic
// "manifest", and every consumer derives ModuleRoot via
// filepath.Dir(manifest), which climbed one level ABOVE the scanned tree.
// That keyed PackageIndex entries as "<dir-basename>.db" while sibling
// imports (`from db import x`) resolved to the absolute module "db.x" — the
// keys never matched, so no caller->callee edge was ever created.
//
// The companion tests in crossfile_walk_python_test.go all inject a
// pyproject.toml via pythonScanFixture; these tests deliberately do NOT,
// so the Pass-3 sibling-resolution path is exercised. If these start
// failing with "0 findings", the synthetic-manifest sentinel in
// ProjectRoot Pass 3 (or its filepath.Dir consumers in resolve.go /
// incremental.go) has regressed.

package graph

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// pythonScanFixtureNoManifest is pythonScanFixture WITHOUT the auto-added
// pyproject.toml. The files are written to a temp dir, nodes are built,
// and the full cross-file resolution pass runs — exactly mirroring what
// the dirscan finalize path does for a manifest-less repo (small CLIs,
// flat script collections, sibling-module layouts).
func pythonScanFixtureNoManifest(t *testing.T, files map[string]string) (*CallGraph, map[string]string) {
	t.Helper()
	root := t.TempDir()
	// Sanity: the test must not accidentally provide a manifest, or it
	// would silently exercise the Pass-1 path instead of Pass-3.
	for name := range files {
		switch filepath.Base(name) {
		case "pyproject.toml", "setup.py", "setup.cfg", "__init__.py":
			t.Fatalf("pythonScanFixtureNoManifest must not contain a manifest, got %q", name)
		}
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
	ResolveCrossFileEdges(cg, root, contents)
	return cg, paths
}

// TestPythonCrossFile_NoManifest_SingleHop_SQLExecute is the canonical
// regression: a 2-file project with no manifest where the handler reads
// request input and forwards it to a SQL-using helper in a sibling file.
// The BATOU-INTERPROC-SQL_QUERY finding MUST fire — before the Pass-3
// anchor fix it did not (0 flows, silently).
func TestPythonCrossFile_NoManifest_SingleHop_SQLExecute(t *testing.T) {
	cg, paths := pythonScanFixtureNoManifest(t, map[string]string{
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
		t.Fatalf("no-manifest cross-file SQL flow was silently dropped; "+
			"expected >=1 BATOU-INTERPROC-SQL_QUERY, got %d findings: %v",
			len(findings), findingRuleIDs(findings))
	}
	// The cross-file caller->callee edge must exist (the concrete symptom
	// the anchor bug suppressed). Without the edge the walker has no pair.
	handleID := paths["app.py"] + ":handle"
	findUserID := paths["db.py"] + ":find_user"
	handle := cg.Nodes[handleID]
	if handle == nil {
		t.Fatalf("expected handle node %q in graph", handleID)
	}
	if !containsStr(handle.Calls, findUserID) {
		t.Errorf("expected cross-file edge handle -> find_user; handle.Calls=%v", handle.Calls)
	}
}

// TestPythonCrossFile_NoManifest_RelativeImport pins that a relative
// sibling import (`from .db import find_user`) also resolves without a
// manifest. The leading dot resolves against the file's own derived
// package, which the Pass-3 anchor now keys consistently with the
// PackageIndex.
func TestPythonCrossFile_NoManifest_RelativeImport(t *testing.T) {
	cg, paths := pythonScanFixtureNoManifest(t, map[string]string{
		"db.py": `def find_user(name):
    cursor.execute("SELECT * FROM users WHERE name='" + name + "'")
`,
		"app.py": `from flask import Request
from .db import find_user

def handle(request: Request):
    find_user(request.args.get('name'))
`,
	})

	primePythonSigs(t, cg, paths)

	findings := WalkCrossFileTaintFlows(cg, nil)
	sqlFindings := filterFindingsByRule(findings, "BATOU-INTERPROC-SQL_QUERY")
	if len(sqlFindings) == 0 {
		t.Fatalf("no-manifest relative-import cross-file SQL flow was dropped; "+
			"expected >=1 BATOU-INTERPROC-SQL_QUERY, got %d findings: %v",
			len(findings), findingRuleIDs(findings))
	}
}

// TestPythonCrossFile_NoManifest_TwoHopChain confirms multi-hop sink
// lifting also works manifest-less: handle -> forward (delegate) ->
// run_cmd (subprocess.run sink), all in sibling files with no manifest.
func TestPythonCrossFile_NoManifest_TwoHopChain(t *testing.T) {
	cg, paths := pythonScanFixtureNoManifest(t, map[string]string{
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

	primePythonSigs(t, cg, paths)

	propStats := PropagateSignaturesAcrossCallgraph(cg, nil)
	if propStats.SinksLifted == 0 {
		t.Fatalf("expected sig propagation to lift >=1 sink without a manifest; got %+v", propStats)
	}

	findings := WalkCrossFileTaintFlows(cg, nil)
	cmdFindings := filterFindingsByRule(findings, "BATOU-INTERPROC-COMMAND_EXEC")
	if len(cmdFindings) == 0 {
		t.Fatalf("no-manifest 2-hop COMMAND_EXEC flow was dropped; got %d findings: %v",
			len(findings), findingRuleIDs(findings))
	}
	sinkSeen := false
	for _, f := range cmdFindings {
		for _, st := range f.TaintPath {
			if st.Kind == rules.TaintStepSink && st.File == paths["runners.py"] {
				sinkSeen = true
			}
		}
	}
	if !sinkSeen {
		t.Errorf("no finding's sink step pointed at runners.py through the manifest-less 2-hop chain; findings=%+v", cmdFindings)
	}
}

// TestPythonCrossFile_NoManifest_CleanSiblingNoEdge is the FP guard: a
// sibling file that does NOT import the SQL helper and passes a hardcoded
// literal must produce no edge and no finding. The Pass-3 anchor fix keys
// modules by bare basename, so this verifies the fix did not collapse all
// siblings into one over-resolving bucket — resolution still requires a
// real import statement.
func TestPythonCrossFile_NoManifest_CleanSiblingNoEdge(t *testing.T) {
	cg, paths := pythonScanFixtureNoManifest(t, map[string]string{
		"db.py": `def find_user(name):
    cursor.execute("SELECT * FROM users WHERE name='" + name + "'")
`,
		// No import of db; hardcoded literal arg; bare call to a same-named
		// function. Must not cross-wire to db.find_user.
		"seed.py": `def admin_seed():
    find_user("alice")
`,
	})

	primePythonSigs(t, cg, paths)

	seedID := paths["seed.py"] + ":admin_seed"
	seed := cg.Nodes[seedID]
	if seed == nil {
		t.Fatalf("expected seed node %q in graph", seedID)
	}
	if len(seed.Calls) != 0 {
		t.Errorf("clean sibling with no import must have no cross-file edge; seed.Calls=%v", seed.Calls)
	}

	findings := WalkCrossFileTaintFlows(cg, nil)
	sqlFindings := filterFindingsByRule(findings, "BATOU-INTERPROC-SQL_QUERY")
	if len(sqlFindings) != 0 {
		t.Errorf("clean sibling (no import, hardcoded arg) must not produce a SQL_QUERY finding; got %d: %+v",
			len(sqlFindings), sqlFindings)
	}
}
