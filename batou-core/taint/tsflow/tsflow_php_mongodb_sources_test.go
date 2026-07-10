package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"

	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// PHP MongoDB additional second-order read sources.
//
// MongoDB has 18 sinks in php_sinks.go but only findOne was modeled as a
// read source. The document-returning reads — findOneAndUpdate /
// findOneAndReplace / findOneAndDelete (return the matched/deleted doc) and
// aggregate (returns pipeline result docs) — return data a previous request
// persisted. Reading it back and passing it to a dangerous sink is classic
// second-order injection.
// =========================================================================

func TestPHP_MongoDB_FindOneAndUpdate_Command(t *testing.T) {
	code := `<?php
function run_task() {
    $doc = $collection->findOneAndUpdate(['_id' => 1], ['$set' => ['seen' => true]]);
    exec($doc);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from MongoDB findOneAndUpdate() to exec()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_MongoDB_FindOneAndReplace_SQLi(t *testing.T) {
	code := `<?php
function search_user($pdo) {
    $doc = $collection->findOneAndReplace(['_id' => 1], ['name' => 'x']);
    $pdo->query("SELECT * FROM users WHERE name = '" . $doc . "'");
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from MongoDB findOneAndReplace() to pdo->query()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_MongoDB_FindOneAndDelete_Command(t *testing.T) {
	code := `<?php
function run_task() {
    $doc = $collection->findOneAndDelete(['_id' => 1]);
    system($doc);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from MongoDB findOneAndDelete() to system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_MongoDB_Aggregate_Command(t *testing.T) {
	code := `<?php
function run_report() {
    $rows = $collection->aggregate([['$match' => ['active' => true]]]);
    exec($rows);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from MongoDB aggregate() to exec()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Negative: sanitizer neutralizes the second-order flow ---

func TestPHP_MongoDB_FindOneAndUpdate_Sanitized(t *testing.T) {
	code := `<?php
function run_task() {
    $doc = $collection->findOneAndUpdate(['_id' => 1], ['$set' => ['seen' => true]]);
    $safe = escapeshellarg($doc);
    exec($safe);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("escapeshellarg() should neutralize command flow from MongoDB findOneAndUpdate()")
	}
}

// --- Negative: a non-source read method must NOT taint (scoping check) ---

func TestPHP_MongoDB_CountDocuments_NoFlow(t *testing.T) {
	code := `<?php
function run_task() {
    $n = $collection->countDocuments(['active' => true]);
    exec($n);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("countDocuments() is not a read source; no command flow expected")
	}
}
