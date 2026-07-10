// Cross-file STORED-STATE taint tests for PHP instance fields (Task A).
//
// PHP method nodes are named `Namespace\Class::method`, so the join works off
// the `::`-aware classQualifier (`App\Repo::find` → "App\Repo"). The field
// write/read shape is `$this->field`. These mirror the Java / Ruby / C#
// stored-state shapes:
//   - positive: store $_GET into $this->field in file A, read it into a sink
//     in file B; same Namespace\Class across files, no call edge — must emit;
//   - param-source negative (field set from a method parameter) — must NOT emit;
//   - sanitized-write negative — must NOT emit;
//   - distinct-class negative (field written in class A, read in class B) —
//     must NOT emit;
//   - same-file cross-method positive (write in one method, read in another
//     method of the SAME file) — must emit: PHP has no tsflow intra-file
//     stored-state channel ($this->x has no field-key path there), so this
//     pass is the only engine that can see the flow;
//   - same-method negative (write+read inside ONE method) — must NOT emit
//     (plain intra-procedural flow, tsflow territory).

package graph

import (
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// phpStoredStateWalk writes a PSR-4 project, builds PHP FuncNodes, resolves
// cross-file edges, and returns the stored-state findings. Reuses the existing
// phpScanFixture (composer.json injection + buildPHPNodes + resolve).
func phpStoredStateWalk(t *testing.T, files map[string]string) []rules.Finding {
	t.Helper()
	cg, _ := phpScanFixture(t, files)
	return WalkCrossFileStoredState(cg)
}

func TestStoredState_PHP_Positive(t *testing.T) {
	f := phpStoredStateWalk(t, map[string]string{
		"app/Store.php": `<?php
namespace App;
class UserController {
    public function load() {
        $this->userQuery = $_GET["q"];
    }
}
`,
		"app/Use.php": `<?php
namespace App;
class UserController {
    public function run() {
        system($this->userQuery);
    }
}
`,
	})
	assertStoredFinding(t, f, "userQuery", true)
}

func TestStoredState_PHP_ParamSourceNotEmitted(t *testing.T) {
	f := phpStoredStateWalk(t, map[string]string{
		"app/Store.php": `<?php
namespace App;
class UserController {
    public function load($data) {
        $this->userQuery = $data;
    }
}
`,
		"app/Use.php": `<?php
namespace App;
class UserController {
    public function run() {
        system($this->userQuery);
    }
}
`,
	})
	assertStoredFinding(t, f, "userQuery", false)
}

func TestStoredState_PHP_SanitizedWriteNotEmitted(t *testing.T) {
	f := phpStoredStateWalk(t, map[string]string{
		"app/Store.php": `<?php
namespace App;
class UserController {
    public function load() {
        $this->userQuery = escapeshellarg($_GET["q"]);
    }
}
`,
		"app/Use.php": `<?php
namespace App;
class UserController {
    public function run() {
        system($this->userQuery);
    }
}
`,
	})
	assertStoredFinding(t, f, "userQuery", false)
}

func TestStoredState_PHP_DistinctClassNotJoined(t *testing.T) {
	f := phpStoredStateWalk(t, map[string]string{
		"app/Store.php": `<?php
namespace App;
class Writer {
    public function load() {
        $this->userQuery = $_GET["q"];
    }
}
`,
		"app/Use.php": `<?php
namespace App;
class Reader {
    public function run() {
        system($this->userQuery);
    }
}
`,
	})
	assertStoredFinding(t, f, "userQuery", false)
}

// PHP same-file cross-method: the write and read live in DIFFERENT methods of
// one class in ONE file. tsflow's intra-file stored-state channel does not
// cover PHP, so the Layer-4 stored-state join is the only engine that can see
// this flow — it must emit (the instance-field-across-methods recall hole).
func TestStoredState_PHP_SameFileCrossMethodEmitted(t *testing.T) {
	f := phpStoredStateWalk(t, map[string]string{
		"app/Single.php": `<?php
namespace App;
class UserController {
    public function load() {
        $this->userQuery = $_GET["q"];
    }
    public function run() {
        system($this->userQuery);
    }
}
`,
	})
	assertStoredFinding(t, f, "userQuery", true)
}

// A write and read inside the SAME method must NOT emit from this channel —
// that is plain intra-procedural flow (tsflow territory in every language),
// and joining a method to itself would double-report it.
func TestStoredState_PHP_SameMethodNotEmitted(t *testing.T) {
	f := phpStoredStateWalk(t, map[string]string{
		"app/Single.php": `<?php
namespace App;
class UserController {
    public function handle() {
        $this->userQuery = $_GET["q"];
        system($this->userQuery);
    }
}
`,
	})
	assertStoredFinding(t, f, "userQuery", false)
}
