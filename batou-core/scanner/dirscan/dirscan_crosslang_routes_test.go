package dirscan

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	// Pull in the rule + taint catalogs + AST analyzers for BOTH languages
	// so the full scanner pipeline builds JS handler/outbound nodes AND
	// Python Flask handler nodes, and so the handler-sink population
	// (ensure*CalleeSinks) finds db.query / cursor.execute. The
	// cross-language matcher itself is compiled into the graph package
	// unconditionally, but the per-file catalogs that feed it must be linked.
	_ "github.com/turenlabs/batou-core/analyzer/jsast"
	_ "github.com/turenlabs/batou-core/analyzer/pyast"
	_ "github.com/turenlabs/batou-core/scanner"
	_ "github.com/turenlabs/batou-core/taint/languages"
	_ "github.com/turenlabs/batou-core/taintrule"
	_ "github.com/turenlabs/batou-rules/rules/injection"
	_ "github.com/turenlabs/batou-rules/rules/jsts"
	_ "github.com/turenlabs/batou-rules/rules/python"
	_ "github.com/turenlabs/batou-rules/rules/validation"
)

// writeCrossLangJSToFlaskProject writes a 2-file, 2-language project under
// root: a JS front-end that issues an outbound request to outboundPath
// with a tainted query param, and a Python Flask back-end whose handler is
// registered for routePath and forwards request input into a SQL sink.
//
// Deliberately non-test, non-fixture path names (frontend/, backend/) so
// isTestFile() does not cap/suppress the resulting finding.
func writeCrossLangJSToFlaskProject(t *testing.T, root, outboundPath, routePath string) {
	t.Helper()
	mustMkdirAll(t, filepath.Join(root, "frontend"))
	mustMkdirAll(t, filepath.Join(root, "backend"))

	js := `// Browser data layer calling our own backend.
function loadItems(req) {
  return fetch("` + outboundPath + `?q=" + req.query.q)
    .then(function (r) { return r.json(); });
}
module.exports.loadItems = loadItems;
`
	py := `from flask import Flask, request
import sqlite3

app = Flask(__name__)
conn = sqlite3.connect("app.db")

@app.route("` + routePath + `")
def items():
    q = request.args["q"]
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM items WHERE name = '" + q + "'")
    return cursor.fetchall()
`
	mustWriteFile(t, filepath.Join(root, "frontend", "client.js"), js)
	mustWriteFile(t, filepath.Join(root, "backend", "server.py"), py)
}

func mustMkdirAll(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// runDirscanForCrossLang drives the full `batou scan DIR` pipeline against
// root (per-file scanner.Scan + shared callgraph + cross-file resolve +
// signature propagation + cross-LANGUAGE service-boundary matcher + JSONL
// emit + persistence), persisting the callgraph at cgPath. Returns whether
// any emitted JSONL line is a BATOU-CROSSLANG-* cross-language finding on a
// non-test path, plus the raw JSONL for failure diagnostics.
//
// Hermetic: runs from a throwaway cwd so a stale repo-root
// .batou/callgraph.json never feeds into or is clobbered by the test, and a
// fresh per-call cgPath keeps the negative case from inheriting positive
// edges (the exact contamination the cross-language acceptance notes warn about).
func runDirscanForCrossLang(t *testing.T, root, cgPath string) (bool, string) {
	t.Helper()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(prev) }()

	var out bytes.Buffer
	err = Run(context.Background(), Options{
		Root:          root,
		Exts:          []string{".js", ".py"},
		Out:           &out,
		ErrOut:        io.Discard,
		CallgraphPath: cgPath,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	sawCrossLang := false
	dec := json.NewDecoder(strings.NewReader(out.String()))
	for {
		var rec map[string]interface{}
		if err := dec.Decode(&rec); err != nil {
			break
		}
		ruleID, _ := rec["rule_id"].(string)
		if !strings.HasPrefix(ruleID, "BATOU-CROSSLANG-") {
			continue
		}
		if rec["cwe"] != "CWE-89" {
			continue
		}
		if rec["is_test_file"] == true {
			continue
		}
		// The taint path must genuinely span both files/languages: a JS
		// source step and a Python sink step.
		if crossLangPathSpansBothFiles(rec) {
			sawCrossLang = true
		}
	}
	return sawCrossLang, out.String()
}

// crossLangPathSpansBothFiles confirms the finding's taint_path has a step
// in a .js file and a (sink) step in a .py file — i.e. it really crosses
// the language boundary rather than being a same-language finding that
// happens to carry the rule prefix.
func crossLangPathSpansBothFiles(rec map[string]interface{}) bool {
	steps, ok := rec["taint_path"].([]interface{})
	if !ok {
		return false
	}
	sawJS, sawPySink := false, false
	for _, s := range steps {
		step, ok := s.(map[string]interface{})
		if !ok {
			continue
		}
		file, _ := step["file"].(string)
		kind, _ := step["kind"].(string)
		if strings.HasSuffix(file, ".js") {
			sawJS = true
		}
		if strings.HasSuffix(file, ".py") && kind == "sink" {
			sawPySink = true
		}
	}
	return sawJS && sawPySink
}

// TestRun_CrossLangJSToFlask_MatchingPath is the end-to-end guard for
// cross-language route taint in the REAL dirscan pipeline (NOT a bare graph-function call).
// A JS outbound `fetch("/api/items?q=" + req.query.q)` must be linked to
// the Flask handler registered for "/api/items" whose body forwards
// request input into cursor.execute(), producing a cross-language CWE-89
// finding that spans both files/languages.
func TestRun_CrossLangJSToFlask_MatchingPath(t *testing.T) {
	root := t.TempDir()
	writeCrossLangJSToFlaskProject(t, root, "/api/items", "/api/items")
	cgPath := filepath.Join(t.TempDir(), "callgraph.json")

	cold, coldOut := runDirscanForCrossLang(t, root, cgPath)
	if !cold {
		t.Fatalf("COLD scan: expected a cross-language CWE-89 finding linking the JS "+
			"outbound request to the Flask /api/items handler SQL sink; output:\n%s", coldOut)
	}

	// WARM rescan against the same persisted callgraph: every file is
	// content-hash-unchanged, so the route metadata (RoutePath /
	// OutboundRequests) must survive the reuse path and STILL fire. This
	// guards the warm-reuse idempotency reset in registerJSFunc /
	// registerPythonFunc.
	warm, warmOut := runDirscanForCrossLang(t, root, cgPath)
	if !warm {
		t.Fatalf("WARM rescan (callgraph reloaded from disk): the cross-language "+
			"CWE-89 finding must STILL fire; output:\n%s", warmOut)
	}
}

// TestRun_CrossLangJSToFlask_MismatchedPath is the negative control: the
// outbound path (/api/products) names no registered route (the handler
// serves /api/items), so NO cross-language finding may be emitted. Uses a
// fresh callgraph so positive-run edges cannot contaminate it.
func TestRun_CrossLangJSToFlask_MismatchedPath(t *testing.T) {
	root := t.TempDir()
	writeCrossLangJSToFlaskProject(t, root, "/api/products", "/api/items")
	cgPath := filepath.Join(t.TempDir(), "callgraph.json")

	saw, out := runDirscanForCrossLang(t, root, cgPath)
	if saw {
		t.Fatalf("mismatched outbound path must NOT emit a cross-language "+
			"finding (no route serves /api/products); output:\n%s", out)
	}
}
