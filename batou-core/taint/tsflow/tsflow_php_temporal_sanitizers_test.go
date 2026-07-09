package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// PHP temporal-parse return-value sanitizers
//
// new DateTime / new DateTimeImmutable / date_create / date_create_immutable /
// strtotime / DateInterval::createFromDateString / Carbon::parse take a
// (possibly permissive) date/time string and return a typed DateTime object
// or an int Unix timestamp. Once converted, the result cannot carry SQL,
// shell, log, file path, HTML, or redirect injection payloads.
//
// Per-feature file (not appended to tsflow_test.go) to avoid sibling-PR
// merge conflicts.
// =========================================================================

func phpHasHighConfFlow(flows []taint.TaintFlow, cat taint.SinkCategory) bool {
	for _, f := range flows {
		if f.Sink.Category == cat && f.Confidence > 0.5 {
			return true
		}
	}
	return false
}

// --- new DateTime / new DateTimeImmutable ---

func TestPHP_Temporal_Safe_NewDateTime_SQL(t *testing.T) {
	code := `<?php
function handler() {
    $name = $_POST["name"];
    $dt = new DateTime($name);
    $pdo = new PDO("sqlite:test.db");
    $pdo->query("SELECT * FROM events WHERE day = '" . $dt . "'");
}
?>`
	flows := Analyze(code, "/app/h.php", rules.LangPHP)
	if phpHasHighConfFlow(flows, taint.SnkSQLQuery) {
		t.Error("new DateTime($input) should neutralize SQL flow (input is converted to a typed DateTime object)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestPHP_Temporal_Safe_NewDateTimeImmutable_SQL(t *testing.T) {
	code := `<?php
function handler() {
    $name = $_POST["name"];
    $dt = new DateTimeImmutable($name);
    $pdo = new PDO("sqlite:test.db");
    $pdo->query("UPDATE events SET seen = 1 WHERE day = '" . $dt . "'");
}
?>`
	flows := Analyze(code, "/app/h.php", rules.LangPHP)
	if phpHasHighConfFlow(flows, taint.SnkSQLQuery) {
		t.Error("new DateTimeImmutable($input) should neutralize SQL flow")
	}
}

func TestPHP_Temporal_Safe_NewDateTime_Command(t *testing.T) {
	code := `<?php
function handler() {
    $name = $_POST["name"];
    $dt = new DateTime($name);
    shell_exec("echo " . $dt);
}
?>`
	flows := Analyze(code, "/app/h.php", rules.LangPHP)
	if phpHasHighConfFlow(flows, taint.SnkCommand) {
		t.Error("new DateTime($input) should neutralize OS command flow")
	}
}

func TestPHP_Temporal_Safe_NewDateTime_Log(t *testing.T) {
	code := `<?php
function handler() {
    $name = $_POST["name"];
    $dt = new DateTime($name);
    error_log("event at " . $dt);
}
?>`
	flows := Analyze(code, "/app/h.php", rules.LangPHP)
	if phpHasHighConfFlow(flows, taint.SnkLog) {
		t.Error("new DateTime($input) should neutralize log flow")
	}
}

// --- date_create / date_create_immutable (procedural aliases) ---

func TestPHP_Temporal_Safe_DateCreate_SQL(t *testing.T) {
	code := `<?php
function handler() {
    $name = $_POST["name"];
    $dt = date_create($name);
    $pdo = new PDO("sqlite:test.db");
    $pdo->query("SELECT * FROM events WHERE day = '" . $dt . "'");
}
?>`
	flows := Analyze(code, "/app/h.php", rules.LangPHP)
	if phpHasHighConfFlow(flows, taint.SnkSQLQuery) {
		t.Error("date_create($input) should neutralize SQL flow")
	}
}

func TestPHP_Temporal_Safe_DateCreateImmutable_SQL(t *testing.T) {
	code := `<?php
function handler() {
    $name = $_POST["name"];
    $dt = date_create_immutable($name);
    $pdo = new PDO("sqlite:test.db");
    $pdo->query("SELECT * FROM events WHERE day = '" . $dt . "'");
}
?>`
	flows := Analyze(code, "/app/h.php", rules.LangPHP)
	if phpHasHighConfFlow(flows, taint.SnkSQLQuery) {
		t.Error("date_create_immutable($input) should neutralize SQL flow")
	}
}

// --- strtotime (returns int|false) ---

func TestPHP_Temporal_Safe_Strtotime_SQL(t *testing.T) {
	code := `<?php
function handler() {
    $name = $_POST["when"];
    $ts = strtotime($name);
    $pdo = new PDO("sqlite:test.db");
    $pdo->query("SELECT * FROM events WHERE created_at = " . $ts);
}
?>`
	flows := Analyze(code, "/app/h.php", rules.LangPHP)
	if phpHasHighConfFlow(flows, taint.SnkSQLQuery) {
		t.Error("strtotime($input) returns int|false; should neutralize SQL flow")
	}
}

func TestPHP_Temporal_Safe_Strtotime_FileWrite(t *testing.T) {
	code := `<?php
function handler() {
    $name = $_POST["when"];
    $ts = strtotime($name);
    file_put_contents("/var/log/events_" . $ts . ".log", "data");
}
?>`
	flows := Analyze(code, "/app/h.php", rules.LangPHP)
	if phpHasHighConfFlow(flows, taint.SnkFileWrite) {
		t.Error("strtotime($input) returns int; should neutralize file path flow")
	}
}

// --- DateInterval::createFromDateString ---

func TestPHP_Temporal_Safe_DateIntervalCreateFromDateString_SQL(t *testing.T) {
	code := `<?php
function handler() {
    $name = $_POST["interval"];
    $iv = DateInterval::createFromDateString($name);
    $pdo = new PDO("sqlite:test.db");
    $pdo->query("SELECT * FROM events WHERE term = '" . $iv . "'");
}
?>`
	flows := Analyze(code, "/app/h.php", rules.LangPHP)
	if phpHasHighConfFlow(flows, taint.SnkSQLQuery) {
		t.Error("DateInterval::createFromDateString($input) should neutralize SQL flow")
	}
}

// --- Carbon::parse (Briannesbitt\Carbon — bundled with Laravel) ---

func TestPHP_Temporal_Safe_CarbonParse_SQL(t *testing.T) {
	code := `<?php
use Carbon\Carbon;
function handler() {
    $name = $_POST["when"];
    $dt = Carbon::parse($name);
    $pdo = new PDO("sqlite:test.db");
    $pdo->query("SELECT * FROM events WHERE day = '" . $dt . "'");
}
?>`
	flows := Analyze(code, "/app/h.php", rules.LangPHP)
	if phpHasHighConfFlow(flows, taint.SnkSQLQuery) {
		t.Error("Carbon::parse($input) should neutralize SQL flow")
	}
}

func TestPHP_Temporal_Safe_CarbonParse_HTML(t *testing.T) {
	code := `<?php
use Carbon\Carbon;
function handler() {
    $name = $_POST["when"];
    $dt = Carbon::parse($name);
    echo "<p>Created: " . $dt . "</p>";
}
?>`
	flows := Analyze(code, "/app/h.php", rules.LangPHP)
	if phpHasHighConfFlow(flows, taint.SnkHTMLOutput) {
		t.Error("Carbon::parse($input) should neutralize HTML output flow")
	}
}

// --- Positive control: without a temporal sanitizer, the same source -> sink
// flow MUST still fire. Confirms the negative tests above are testing the
// sanitizer effect, not just absent source/sink coverage. ---

func TestPHP_Temporal_Unsafe_NoSanitizer_SQL(t *testing.T) {
	code := `<?php
function handler() {
    $name = $_POST["name"];
    $pdo = new PDO("sqlite:test.db");
    $pdo->query("SELECT * FROM events WHERE day = '" . $name . "'");
}
?>`
	flows := Analyze(code, "/app/h.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for $_POST -> string concat -> PDO::query() (positive control)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf=%.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
