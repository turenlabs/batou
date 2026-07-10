// Cross-file PHP interproc walker tests (PR-Gphp).
//
// These tests exercise the full PHP cross-file pipeline:
//   1. buildPHPNodes registers FuncNodes for each .php file.
//   2. ResolveCrossFileEdges (PSR-4 + `use` imports) wires caller→callee
//      edges between the files.
//   3. WalkCrossFileTaintFlows dispatches to AnalyzeCallerImpactPHP for
//      PHP callees and emits BATOU-INTERPROC-<CAT> findings.
//
// Negative tests assert that sanitized / constant args produce zero
// findings even when the (caller, callee) pair is fully formed and the
// callee sink is populated.
//
// PHP-specific notes vs. the Ruby / Lua equivalents:
//   - The resolver wires cross-file edges for STATIC / scoped calls
//     (`Repo::find($n)` with `use App\Repo;`) and for FQN calls. These
//     tests use the scoped-call shape. Member calls on a local variable
//     (`$r->find($n)`) ALSO resolve cross-file now via build-time
//     receiver-type recovery (the builder rewrites `$r->find` →
//     `Repo::find` when the receiver's class came from `new Repo()` / a
//     typed `Repo $r` param / a `private Repo $r;` property) — see
//     crossfile_walk_php_instance_test.go for that path.
//   - Callee method nodes are named `App\Cls::method`; phpBaseName strips
//     the `::` scope and `\` namespace so the call-index basename matches.
//   - The PHP builder does not populate typed Params/SourceParams, so the
//     walker lazy-populates the callee's SinkCalls (ArgFromParam == -1)
//     and gates Path A on caller-side taint of the passed argument.

package graph

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// phpScanFixture builds a tiny PSR-4 project: writes files (adding a
// composer.json mapping `App\` → `app/` when none is present), builds PHP
// FuncNodes, resolves cross-file edges, and returns the populated
// CallGraph plus the absolute path to each file by relative name.
func phpScanFixture(t *testing.T, files map[string]string) (*CallGraph, map[string]string) {
	t.Helper()
	root := t.TempDir()
	if _, present := files["composer.json"]; !present {
		files["composer.json"] = `{"autoload":{"psr-4":{"App\\":"app/"}}}`
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
		if !strings.HasSuffix(rel, ".php") {
			continue
		}
		buildPHPNodes(cg, abs, content, nil)
		contents[abs] = []byte(content)
	}
	ResolveCrossFileEdges(cg, root, contents)
	return cg, paths
}

// TestPHPCrossFile_SingleHop_SqlSink covers the canonical 1-hop Path A:
// a controller reads $_GET into a local, then forwards it to a DAO method
// (defined in another file) that concatenates it into $db->query(...).
// Expected: BATOU-INTERPROC-SQL_QUERY with a sink step in the DAO file.
func TestPHPCrossFile_SingleHop_SqlSink(t *testing.T) {
	cg, paths := phpScanFixture(t, map[string]string{
		"app/Repo.php": `<?php
namespace App;
class Repo {
    public static function find($n) {
        global $db;
        return $db->query("SELECT * FROM users WHERE name = '" . $n . "'");
    }
}
`,
		"app/Ctl.php": `<?php
namespace App;
use App\Repo;
class Ctl {
    public function show() {
        $n = $_GET["n"];
        return Repo::find($n);
    }
}
`,
	})

	findings := WalkCrossFileTaintFlows(cg, nil)
	sqlFindings := filterFindingsByRule(findings, "BATOU-INTERPROC-SQL_QUERY")
	if len(sqlFindings) == 0 {
		t.Fatalf("expected BATOU-INTERPROC-SQL_QUERY via Repo::find(); got %d findings: %v",
			len(findings), findingRuleIDs(findings))
	}
	// At least one finding's sink step must point at the DAO file.
	sinkSeen := false
	for _, f := range sqlFindings {
		for _, st := range f.TaintPath {
			if st.Kind == rules.TaintStepSink && st.File == paths["app/Repo.php"] {
				sinkSeen = true
			}
		}
	}
	if !sinkSeen {
		t.Errorf("no finding had a sink step in app/Repo.php; findings=%+v", sqlFindings)
	}
	// Every emitted finding's Language must be PHP — never Go.
	for _, f := range findings {
		if f.Language != "" && f.Language != rules.LangPHP {
			t.Errorf("finding has wrong Language %q: %+v", f.Language, f)
		}
	}
}

// TestPHPCrossFile_DirectSourceArg covers Path A when the superglobal is
// passed directly at the call site (`Repo::find($_GET["n"])`) without an
// intermediate variable.
func TestPHPCrossFile_DirectSourceArg(t *testing.T) {
	cg, _ := phpScanFixture(t, map[string]string{
		"app/Repo.php": `<?php
namespace App;
class Repo {
    public static function find($n) {
        global $db;
        return $db->query("SELECT * FROM t WHERE x = '" . $n . "'");
    }
}
`,
		"app/Ctl.php": `<?php
namespace App;
use App\Repo;
class Ctl {
    public function show() {
        return Repo::find($_GET["n"]);
    }
}
`,
	})

	findings := WalkCrossFileTaintFlows(cg, nil)
	if len(filterFindingsByRule(findings, "BATOU-INTERPROC-SQL_QUERY")) == 0 {
		t.Fatalf("expected BATOU-INTERPROC-SQL_QUERY for direct $_GET arg; got %d findings: %v",
			len(findings), findingRuleIDs(findings))
	}
}

// TestPHPCrossFile_Sanitized_NoFinding asserts that wrapping the user
// input in intval(...) before passing it across the boundary suppresses
// the finding — even though the (caller, callee) pair and the callee sink
// are both present.
func TestPHPCrossFile_Sanitized_NoFinding(t *testing.T) {
	cg, _ := phpScanFixture(t, map[string]string{
		"app/Repo.php": `<?php
namespace App;
class Repo {
    public static function find($n) {
        global $db;
        return $db->query("SELECT * FROM users WHERE id = " . $n);
    }
}
`,
		"app/Ctl.php": `<?php
namespace App;
use App\Repo;
class Ctl {
    public function show() {
        $n = intval($_GET["n"]);
        return Repo::find($n);
    }
}
`,
	})

	findings := WalkCrossFileTaintFlows(cg, nil)
	if got := len(filterFindingsByRule(findings, "BATOU-INTERPROC-SQL_QUERY")); got != 0 {
		t.Errorf("intval-sanitized input should not produce a SQL_QUERY finding; got %d: %v",
			got, findingRuleIDs(findings))
	}
}

// TestPHPCrossFile_ConstantArg_NoFinding asserts that a constant argument
// (no taint source) produces zero findings even though the callee sink is
// populated and the cross-file edge exists. This pins that the walker
// gates on caller-side taint, not merely on the presence of a sink.
func TestPHPCrossFile_ConstantArg_NoFinding(t *testing.T) {
	cg, _ := phpScanFixture(t, map[string]string{
		"app/Repo.php": `<?php
namespace App;
class Repo {
    public static function find($n) {
        global $db;
        return $db->query("SELECT * FROM users WHERE name = '" . $n . "'");
    }
}
`,
		"app/Ctl.php": `<?php
namespace App;
use App\Repo;
class Ctl {
    public function show() {
        $n = "admin";
        return Repo::find($n);
    }
}
`,
	})

	findings := WalkCrossFileTaintFlows(cg, nil)
	if got := len(filterFindingsByRule(findings, "BATOU-INTERPROC-SQL_QUERY")); got != 0 {
		t.Errorf("constant arg should not produce a SQL_QUERY finding; got %d: %v",
			got, findingRuleIDs(findings))
	}
}

// TestPHPCrossFile_TaintedReturn_SqlSink covers Path B: a callee returns
// user-controlled data (`return $_GET['q'];`); ensurePHPCalleeReturns
// tags TaintedReturns; the caller stores the result and forwards it to a
// SQL sink.
func TestPHPCrossFile_TaintedReturn_SqlSink(t *testing.T) {
	cg, _ := phpScanFixture(t, map[string]string{
		"app/Input.php": `<?php
namespace App;
class Input {
    public static function read() {
        return $_GET["q"];
    }
}
`,
		"app/Ctl.php": `<?php
namespace App;
use App\Input;
class Ctl {
    public function show() {
        global $db;
        $q = Input::read();
        return $db->query("SELECT * FROM t WHERE x = '" . $q . "'");
    }
}
`,
	})

	findings := WalkCrossFileTaintFlows(cg, nil)
	if len(filterFindingsByRule(findings, "BATOU-INTERPROC-SQL_QUERY")) == 0 {
		t.Fatalf("expected BATOU-INTERPROC-SQL_QUERY via tainted-return Path B; got %d findings: %v",
			len(findings), findingRuleIDs(findings))
	}
}
