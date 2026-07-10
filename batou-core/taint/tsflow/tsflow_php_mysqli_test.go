package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// PHP — mysqli SQL injection sinks (multi_query / real_query procedural +
// OO; query OO form). Complements the existing php.mysqli.query (procedural)
// entry. mysqli_multi_query / $mysqli->multi_query() additionally allow
// stacked statements ("id=1; DROP TABLE users;"), which is why they get
// their own coverage rather than relying on the single-statement query()
// entry.
// =========================================================================

// --- Procedural forms ---

func TestPHP_Mysqli_MultiQuery_Procedural_SQLInjection(t *testing.T) {
	code := `<?php
function runReport($link) {
    $name = $_GET['name'];
    $sql = "SELECT * FROM users WHERE name = '" . $name . "'; SELECT count(*) FROM users";
    mysqli_multi_query($link, $sql);
}
?>`
	flows := Analyze(code, "/app/src/report.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for $_GET -> concat -> mysqli_multi_query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPHP_Mysqli_RealQuery_Procedural_SQLInjection(t *testing.T) {
	code := `<?php
function logEvent($link) {
    $tag = $_POST['tag'];
    $sql = "INSERT INTO events (tag) VALUES ('" . $tag . "')";
    mysqli_real_query($link, $sql);
}
?>`
	flows := Analyze(code, "/app/src/events.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for $_POST -> concat -> mysqli_real_query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Object-oriented forms ---

func TestPHP_Mysqli_OO_Query_SQLInjection(t *testing.T) {
	code := `<?php
function findUser($mysqli) {
    $id = $_REQUEST['id'];
    $sql = "SELECT * FROM users WHERE id = " . $id;
    $mysqli->query($sql);
}
?>`
	flows := Analyze(code, "/app/src/users.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for $_REQUEST -> concat -> $mysqli->query()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPHP_Mysqli_OO_MultiQuery_SQLInjection(t *testing.T) {
	code := `<?php
function batchInsert($mysqli) {
    $name = $_GET['name'];
    $sql = "INSERT INTO a (n) VALUES ('" . $name . "'); INSERT INTO b (n) VALUES ('" . $name . "')";
    $mysqli->multi_query($sql);
}
?>`
	flows := Analyze(code, "/app/src/batch.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for $_GET -> concat -> $mysqli->multi_query()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPHP_Mysqli_OO_RealQuery_SQLInjection(t *testing.T) {
	code := `<?php
function streamUpdate($mysqli) {
    $tag = $_POST['tag'];
    $sql = "UPDATE events SET status = '" . $tag . "' WHERE id = 1";
    $mysqli->real_query($sql);
}
?>`
	flows := Analyze(code, "/app/src/stream.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for $_POST -> concat -> $mysqli->real_query()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Negative tests: constant SQL should NOT produce a flow ---

func TestPHP_Mysqli_MultiQuery_ConstantSQL_NoFlow(t *testing.T) {
	code := `<?php
function seedDB($link) {
    $sql = "INSERT INTO settings (k, v) VALUES ('locale', 'en'); INSERT INTO settings (k, v) VALUES ('tz', 'UTC')";
    mysqli_multi_query($link, $sql);
}
?>`
	flows := Analyze(code, "/app/src/seed.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did not expect SQL injection flow for constant SQL into mysqli_multi_query")
		for _, f := range flows {
			t.Logf("  spurious flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPHP_Mysqli_OO_Query_ConstantSQL_NoFlow(t *testing.T) {
	code := `<?php
function activeUserCount($mysqli) {
    $sql = "SELECT COUNT(*) FROM users WHERE active = 1";
    return $mysqli->query($sql);
}
?>`
	flows := Analyze(code, "/app/src/dashboard.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did not expect SQL injection flow for constant SQL into $mysqli->query()")
		for _, f := range flows {
			t.Logf("  spurious flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}
