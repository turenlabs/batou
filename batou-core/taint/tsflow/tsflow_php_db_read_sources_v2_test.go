package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// PHP — additional second-order database-read sources (v2)
//
// Covers: native pgsql ext (pg_fetch_*), mysqli object/row/all/column fetch
// variants, Doctrine DBAL Connection/Result fetch* methods, and CodeIgniter 4
// ResultInterface row generators. Each is a SrcDatabase source: data read from
// a store that may contain attacker-supplied content written earlier. Flowing
// that data into a command/deserialize/eval/HTML sink is second-order injection.
// =========================================================================

// --- Native PostgreSQL (pgsql extension) ---

func TestPHP_PG_FetchAssoc_Deserialization(t *testing.T) {
	code := `<?php
function load_row($conn) {
    $r = pg_query($conn, "SELECT prefs FROM users WHERE id = 1");
    $row = pg_fetch_assoc($r);
    $obj = unserialize($row);
}
?>`
	flows := Analyze(code, "/app/lib/pg.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow from pg_fetch_assoc() to unserialize()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Source.ID)
		}
	}
}

func TestPHP_PG_FetchObject_Command(t *testing.T) {
	code := `<?php
function run_stored($conn) {
    $r = pg_query($conn, "SELECT cmd FROM jobs LIMIT 1");
    $job = pg_fetch_object($r);
    exec($job);
}
?>`
	flows := Analyze(code, "/app/lib/pg.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from pg_fetch_object() to exec()")
	}
}

func TestPHP_PG_FetchAll_XSS(t *testing.T) {
	code := `<?php
function dump_all($conn) {
    $r = pg_query($conn, "SELECT * FROM comments");
    $rows = pg_fetch_all($r);
    printf($rows);
}
?>`
	flows := Analyze(code, "/app/lib/pg.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow from pg_fetch_all() to printf()")
	}
}

func TestPHP_PG_FetchResult_Command(t *testing.T) {
	code := `<?php
function run_one($conn) {
    $r = pg_query($conn, "SELECT cmd FROM jobs");
    $cmd = pg_fetch_result($r, 0, 'cmd');
    system($cmd);
}
?>`
	flows := Analyze(code, "/app/lib/pg.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from pg_fetch_result() to system()")
	}
}

// --- mysqli additional fetch variants ---

func TestPHP_Mysqli_FetchObject_Procedural_Command(t *testing.T) {
	code := `<?php
function run_stored($link) {
    $res = mysqli_query($link, "SELECT cmd FROM jobs LIMIT 1");
    $row = mysqli_fetch_object($res);
    exec($row);
}
?>`
	flows := Analyze(code, "/app/lib/db.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from mysqli_fetch_object() to exec()")
	}
}

func TestPHP_Mysqli_FetchAll_OO_Deserialization(t *testing.T) {
	code := `<?php
function load_all($result) {
    $rows = $result->fetch_all(MYSQLI_ASSOC);
    $obj = unserialize($rows);
}
?>`
	flows := Analyze(code, "/app/lib/db.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow from mysqli_result->fetch_all() to unserialize()")
	}
}

func TestPHP_Mysqli_FetchColumn_OO_Eval(t *testing.T) {
	code := `<?php
function run_blob($result) {
    $blob = $result->fetch_column(0);
    eval($blob);
}
?>`
	flows := Analyze(code, "/app/lib/db.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow from mysqli_result->fetch_column() to eval()")
	}
}

// --- Doctrine DBAL Connection/Result fetch* ---

func TestPHP_DoctrineDBAL_FetchAssociative_Command(t *testing.T) {
	code := `<?php
function run_task($conn) {
    $row = $conn->fetchAssociative("SELECT cmd FROM jobs WHERE id = 1");
    exec($row);
}
?>`
	flows := Analyze(code, "/app/src/Repository/JobRepository.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from Connection::fetchAssociative() to exec()")
	}
}

func TestPHP_DoctrineDBAL_FetchAllAssociative_Deserialization(t *testing.T) {
	code := `<?php
function load_all($conn) {
    $rows = $conn->fetchAllAssociative("SELECT blob FROM cache");
    $obj = unserialize($rows);
}
?>`
	flows := Analyze(code, "/app/src/Repository/CacheRepository.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow from Connection::fetchAllAssociative() to unserialize()")
	}
}

func TestPHP_DoctrineDBAL_FetchOne_Command(t *testing.T) {
	code := `<?php
function run_one($conn) {
    $cmd = $conn->fetchOne("SELECT cmd FROM jobs LIMIT 1");
    system($cmd);
}
?>`
	flows := Analyze(code, "/app/src/Repository/JobRepository.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from Connection::fetchOne() to system()")
	}
}

func TestPHP_DoctrineDBAL_FetchFirstColumn_XSS(t *testing.T) {
	code := `<?php
function dump_names($conn) {
    $names = $conn->fetchFirstColumn("SELECT name FROM users");
    printf($names);
}
?>`
	flows := Analyze(code, "/app/src/Repository/UserRepository.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow from Connection::fetchFirstColumn() to printf()")
	}
}

// --- CodeIgniter 4 ResultInterface ---

func TestPHP_CodeIgniter_GetResultArray_Command(t *testing.T) {
	code := `<?php
function run_jobs($query) {
    $rows = $query->getResultArray();
    exec($rows);
}
?>`
	flows := Analyze(code, "/app/Models/JobModel.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from CI4 getResultArray() to exec()")
	}
}

func TestPHP_CodeIgniter_GetRowArray_Deserialization(t *testing.T) {
	code := `<?php
function load_one($query) {
    $row = $query->getRowArray();
    $obj = unserialize($row);
}
?>`
	flows := Analyze(code, "/app/Models/CacheModel.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow from CI4 getRowArray() to unserialize()")
	}
}

func TestPHP_CodeIgniter_GetResultObject_XSS(t *testing.T) {
	code := `<?php
function list_comments($query) {
    $rows = $query->getResultObject();
    printf($rows);
}
?>`
	flows := Analyze(code, "/app/Models/CommentModel.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow from CI4 getResultObject() to printf()")
	}
}

func TestPHP_CodeIgniter_GetCustomRowObject_Eval(t *testing.T) {
	code := `<?php
function load_entity($query) {
    $entity = $query->getCustomRowObject(0, 'App\\Entities\\Script');
    eval($entity);
}
?>`
	flows := Analyze(code, "/app/Models/ScriptModel.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow from CI4 getCustomRowObject() to eval()")
	}
}

// --- Negative regression: constant strings must NOT fire the new sources ---

func TestPHP_DBReadSourcesV2_LiteralNotASource(t *testing.T) {
	code := `<?php
function constants_only() {
    $a = "a:0:{}";
    $obj = unserialize($a);
    $b = "ls -la";
    system($b);
}
?>`
	flows := Analyze(code, "/app/lib/x.php", rules.LangPHP)
	newIDs := map[string]bool{
		"php.pg.fetch":                       true,
		"php.pg.fetch_all":                   true,
		"php.mysqli.fetch_object_row":        true,
		"php.doctrine.dbal.fetchassociative": true,
		"php.doctrine.dbal.fetchnumeric":     true,
		"php.codeigniter.result.getarray":    true,
		"php.codeigniter.result.getobject":   true,
	}
	for _, f := range flows {
		if newIDs[f.Source.ID] {
			t.Errorf("source %s fired on constant string (over-broad pattern)", f.Source.ID)
		}
	}
}

// --- Registration: the new source IDs must be present in the PHP catalog ---

func TestPHP_DBReadSourcesV2_Registered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangPHP)
	if cat == nil {
		t.Fatal("PHP catalog not loaded")
	}
	have := map[string]bool{}
	for _, s := range cat.Sources() {
		have[s.ID] = true
	}
	want := []string{
		"php.pg.fetch",
		"php.pg.fetch_all",
		"php.mysqli.fetch_object_row",
		"php.doctrine.dbal.fetchassociative",
		"php.doctrine.dbal.fetchnumeric",
		"php.codeigniter.result.getarray",
		"php.codeigniter.result.getobject",
	}
	for _, id := range want {
		if !have[id] {
			t.Errorf("expected PHP source %q to be registered", id)
		}
	}
}
