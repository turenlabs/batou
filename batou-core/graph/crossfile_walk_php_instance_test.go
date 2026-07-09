// Cross-file PHP INSTANCE-method resolution tests.
//
// These pin the build-time receiver-type-recovery fix: a member call on a
// local variable / typed param / typed property whose concrete class was
// declared in the same body (`$repo = new Repo(); $repo->runQuery($id);`)
// must resolve cross-file to the callee `App\Repo::runQuery` exactly like
// the static form `Repo::runQuery($id)` already does.
//
// Before the fix, the PHP builder recorded `$repo->runQuery` as the
// unresolvable raw form "$repo.runQuery" — the resolver split it into
// alias="$repo" (the lowercase local var) + method "runQuery", found no
// class named "$repo", and returned "no opinion". The fix rewrites the
// receiver to its concrete class at build time so the qualified
// `Repo::runQuery` lookup pins it.
//
// load-bearing: TestPHPCrossFile_Instance_NewLocal_SqlSink and the
// typed-param / typed-property variants FAIL on the pre-fix builder
// (member call never resolves → pairs=0 → 0 findings). The negative tests
// pin that the rewrite is type-anchored (a sanitized arg suppresses, and a
// receiver bound to a *different* class never mislinks to a same-named
// method on the wrong class).

package graph

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// phpInstanceSinkSeen reports whether any SQL_QUERY finding has a sink step
// landing in the given absolute file path.
func phpInstanceSinkSeen(findings []rules.Finding, sinkFile string) bool {
	for _, f := range filterFindingsByRule(findings, "BATOU-INTERPROC-SQL_QUERY") {
		for _, st := range f.TaintPath {
			if st.Kind == rules.TaintStepSink && st.File == sinkFile {
				return true
			}
		}
	}
	return false
}

// TestPHPCrossFile_Instance_NewLocal_SqlSink is the canonical instance-method
// cross-file flow: a controller reads $_GET into a local, constructs a Repo
// via `new Repo()`, and forwards the tainted local through `$repo->runQuery`
// to a DAO method (in another file) that concatenates it into $db->query.
// Expected: BATOU-INTERPROC-SQL_QUERY with a sink step in the DAO file.
func TestPHPCrossFile_Instance_NewLocal_SqlSink(t *testing.T) {
	cg, paths := phpScanFixture(t, map[string]string{
		"app/Repo.php": `<?php
namespace App;
class Repo {
    public function runQuery($id) {
        global $db;
        return $db->query("SELECT * FROM t WHERE id = " . $id);
    }
}
`,
		"app/Ctl.php": `<?php
namespace App;
use App\Repo;
class Ctl {
    public function handle() {
        $id = $_GET['id'];
        $repo = new Repo();
        $repo->runQuery($id);
    }
}
`,
	})

	findings := WalkCrossFileTaintFlows(cg, nil)
	if len(filterFindingsByRule(findings, "BATOU-INTERPROC-SQL_QUERY")) == 0 {
		t.Fatalf("expected BATOU-INTERPROC-SQL_QUERY via $repo->runQuery() instance call; got %d findings: %v",
			len(findings), findingRuleIDs(findings))
	}
	if !phpInstanceSinkSeen(findings, paths["app/Repo.php"]) {
		t.Errorf("no finding had a sink step in app/Repo.php; findings=%v", findingRuleIDs(findings))
	}
	for _, f := range findings {
		if f.Language != "" && f.Language != rules.LangPHP {
			t.Errorf("finding has wrong Language %q: %+v", f.Language, f)
		}
	}
}

// TestPHPCrossFile_Instance_TypedParam_SqlSink covers a typed parameter as
// the receiver (`function handle(Repo $repo)`), the DI-injected-method
// shape. The receiver's class is recovered from the parameter type so the
// member call resolves cross-file.
func TestPHPCrossFile_Instance_TypedParam_SqlSink(t *testing.T) {
	cg, paths := phpScanFixture(t, map[string]string{
		"app/Repo.php": `<?php
namespace App;
class Repo {
    public function runQuery($id) {
        global $db;
        return $db->query("SELECT * FROM t WHERE id = " . $id);
    }
}
`,
		"app/Ctl.php": `<?php
namespace App;
use App\Repo;
class Ctl {
    public function handle(Repo $repo) {
        $id = $_GET['id'];
        $repo->runQuery($id);
    }
}
`,
	})

	findings := WalkCrossFileTaintFlows(cg, nil)
	if len(filterFindingsByRule(findings, "BATOU-INTERPROC-SQL_QUERY")) == 0 {
		t.Fatalf("expected BATOU-INTERPROC-SQL_QUERY via typed-param receiver; got %d findings: %v",
			len(findings), findingRuleIDs(findings))
	}
	if !phpInstanceSinkSeen(findings, paths["app/Repo.php"]) {
		t.Errorf("no finding had a sink step in app/Repo.php; findings=%v", findingRuleIDs(findings))
	}
}

// TestPHPCrossFile_Instance_TypedProperty_SqlSink covers a typed property as
// the receiver (`private Repo $repo; ... $this->repo->runQuery(...)`), the
// dominant constructor-injection OO shape. The receiver's class is recovered
// from the property declaration.
func TestPHPCrossFile_Instance_TypedProperty_SqlSink(t *testing.T) {
	cg, paths := phpScanFixture(t, map[string]string{
		"app/Repo.php": `<?php
namespace App;
class Repo {
    public function runQuery($id) {
        global $db;
        return $db->query("SELECT * FROM t WHERE id = " . $id);
    }
}
`,
		"app/Ctl.php": `<?php
namespace App;
use App\Repo;
class Ctl {
    private Repo $repo;
    public function handle() {
        $id = $_GET['id'];
        $this->repo->runQuery($id);
    }
}
`,
	})

	findings := WalkCrossFileTaintFlows(cg, nil)
	if len(filterFindingsByRule(findings, "BATOU-INTERPROC-SQL_QUERY")) == 0 {
		t.Fatalf("expected BATOU-INTERPROC-SQL_QUERY via typed-property receiver; got %d findings: %v",
			len(findings), findingRuleIDs(findings))
	}
	if !phpInstanceSinkSeen(findings, paths["app/Repo.php"]) {
		t.Errorf("no finding had a sink step in app/Repo.php; findings=%v", findingRuleIDs(findings))
	}
}

// TestPHPCrossFile_Instance_Sanitized_NoFinding pins that the instance path
// still honours sanitization: wrapping the user input in intval() before the
// instance call suppresses the finding even though the resolved edge exists.
func TestPHPCrossFile_Instance_Sanitized_NoFinding(t *testing.T) {
	cg, _ := phpScanFixture(t, map[string]string{
		"app/Repo.php": `<?php
namespace App;
class Repo {
    public function runQuery($id) {
        global $db;
        return $db->query("SELECT * FROM t WHERE id = " . $id);
    }
}
`,
		"app/Ctl.php": `<?php
namespace App;
use App\Repo;
class Ctl {
    public function handle() {
        $id = intval($_GET['id']);
        $repo = new Repo();
        $repo->runQuery($id);
    }
}
`,
	})

	findings := WalkCrossFileTaintFlows(cg, nil)
	if got := len(filterFindingsByRule(findings, "BATOU-INTERPROC-SQL_QUERY")); got != 0 {
		t.Errorf("intval-sanitized instance call should not produce a SQL_QUERY finding; got %d: %v",
			got, findingRuleIDs(findings))
	}
}

// TestPHPCrossFile_Instance_NoOverLink pins the anti-over-link guard: a
// receiver bound to SafeRepo (a parameterized DAO, no sink) must NOT mislink
// to the same-named runQuery() on the *vulnerable* VulnRepo in another file.
// The rewrite is type-anchored to the receiver's declared class, so the flow
// resolves to SafeRepo::runQuery (which uses a prepared statement) and emits
// nothing.
func TestPHPCrossFile_Instance_NoOverLink(t *testing.T) {
	cg, _ := phpScanFixture(t, map[string]string{
		"app/VulnRepo.php": `<?php
namespace App;
class VulnRepo {
    public function runQuery($id) {
        global $db;
        return $db->query("SELECT * FROM t WHERE id = " . $id);
    }
}
`,
		"app/SafeRepo.php": `<?php
namespace App;
class SafeRepo {
    public function runQuery($id) {
        global $db;
        $stmt = $db->prepare("SELECT * FROM t WHERE id = ?");
        return $stmt->execute([$id]);
    }
}
`,
		"app/Ctl.php": `<?php
namespace App;
use App\SafeRepo;
class Ctl {
    public function handle() {
        $id = $_GET['id'];
        $repo = new SafeRepo();
        $repo->runQuery($id);
    }
}
`,
	})

	findings := WalkCrossFileTaintFlows(cg, nil)
	// The receiver is SafeRepo, whose runQuery uses a prepared statement — no
	// sink — so there must be zero SQL_QUERY findings. If the rewrite were
	// bare-suffix (matching any `runQuery`) it would mislink to VulnRepo and
	// emit a (false) finding.
	for _, f := range filterFindingsByRule(findings, "BATOU-INTERPROC-SQL_QUERY") {
		// Defensive: assert no finding's sink step lands in the vulnerable file.
		for _, st := range f.TaintPath {
			if st.Kind == rules.TaintStepSink && strings.Contains(st.File, "VulnRepo.php") {
				t.Errorf("instance receiver bound to SafeRepo mislinked to VulnRepo::runQuery (over-link): %+v", f)
			}
		}
	}
	if got := len(filterFindingsByRule(findings, "BATOU-INTERPROC-SQL_QUERY")); got != 0 {
		t.Errorf("SafeRepo (prepared-statement) receiver should produce no SQL_QUERY finding; got %d: %v",
			got, findingRuleIDs(findings))
	}
}

// TestPHPCrossFile_Instance_UntypedReceiver_NoMislink pins the pass-through
// guarantee: a receiver with NO recoverable type (assigned from a function
// call / DI container fetch, no `new T()` and no type annotation) must NOT
// be rewritten — it stays the unresolvable `$svc.runQuery` form and resolves
// to nothing, exactly as before the fix. This guards against a future change
// that inferred a type too loosely and mislinked an unknown receiver to a
// same-named method on an unrelated class.
func TestPHPCrossFile_Instance_UntypedReceiver_NoMislink(t *testing.T) {
	cg, _ := phpScanFixture(t, map[string]string{
		"app/Repo.php": `<?php
namespace App;
class Repo {
    public function runQuery($id) {
        global $db;
        return $db->query("SELECT * FROM t WHERE id = " . $id);
    }
}
`,
		"app/Ctl.php": `<?php
namespace App;
class Ctl {
    public function handle($container) {
        $id = $_GET['id'];
        $svc = $container->make('repo');
        $svc->runQuery($id);
    }
}
`,
	})

	findings := WalkCrossFileTaintFlows(cg, nil)
	// $svc has no recoverable class type, so $svc->runQuery must not resolve
	// to App\Repo::runQuery. Zero SQL_QUERY findings expected.
	if got := len(filterFindingsByRule(findings, "BATOU-INTERPROC-SQL_QUERY")); got != 0 {
		t.Errorf("untyped receiver ($svc from container) must not mislink to App\\Repo::runQuery; got %d: %v",
			got, findingRuleIDs(findings))
	}
}
