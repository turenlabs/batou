package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// PHP DataStax/php-driver + duoshuo/mroosz/php-cassandra
// CQL injection tests (CWE-943).
//
// Mirrors kotlin.cassandra.*, groovy.cassandra.*, csharp.cassandra.*,
// rust.scylla.*, swift.cassandra.* coverage for the PHP ecosystem.
// =========================================================================

// --- DataStax: $session->execute($cql) ---

func TestPHP_Cassandra_Session_Execute(t *testing.T) {
	code := `<?php
function fetch_user($session) {
    $name = $_GET['name'];
    $cql = "SELECT * FROM users WHERE name = '" . $name . "'";
    return $session->execute($cql);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected CQL-injection flow for $_GET -> $session->execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- DataStax: $session->executeAsync($cql) ---

func TestPHP_Cassandra_Session_ExecuteAsync(t *testing.T) {
	code := `<?php
function fetch_user_async($session) {
    $id = $_POST['id'];
    $cql = "SELECT * FROM users WHERE id = " . $id;
    return $session->executeAsync($cql);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected CQL-injection flow for $_POST -> $session->executeAsync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- DataStax: new SimpleStatement($cql) constructor ---

func TestPHP_Cassandra_SimpleStatement_New(t *testing.T) {
	code := `<?php
use Cassandra\SimpleStatement;

function build_stmt($session) {
    $tag = $_REQUEST['tag'];
    $cql = "SELECT * FROM posts WHERE tag = '" . $tag . "'";
    $stmt = new SimpleStatement($cql);
    return $session->execute($stmt);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected CQL-injection flow for $_REQUEST -> new SimpleStatement")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- php-cassandra (duoshuo): $connection->querySync($cql) ---

func TestPHP_Cassandra_Connection_QuerySync(t *testing.T) {
	code := `<?php
function search_sync($connection) {
    $term = $_GET['q'];
    $cql = "SELECT * FROM logs WHERE message = '" . $term . "'";
    $response = $connection->querySync($cql);
    return $response->fetchAll();
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected CQL-injection flow for $_GET -> $connection->querySync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- php-cassandra (duoshuo): $connection->queryAsync($cql) ---

func TestPHP_Cassandra_Connection_QueryAsync(t *testing.T) {
	code := `<?php
function search_async($connection) {
    $email = $_POST['email'];
    $cql = "DELETE FROM users WHERE email = '" . $email . "'";
    return $connection->queryAsync($cql);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected CQL-injection flow for $_POST -> $connection->queryAsync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Receiver alias: $sess->execute($cql) (short-name receiver) ---

func TestPHP_Cassandra_Sess_Execute(t *testing.T) {
	code := `<?php
function via_short_alias($sess) {
    $userid = $_GET['uid'];
    $cql = "UPDATE users SET seen = now() WHERE id = " . $userid;
    return $sess->execute($cql);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected CQL-injection flow for $_GET -> $sess->execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Safe: parameterized literal CQL with no user input — no flow expected ---

func TestPHP_Cassandra_Safe_LiteralQuery(t *testing.T) {
	code := `<?php
function list_users($session) {
    return $session->execute('SELECT * FROM users LIMIT 10');
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	for _, f := range flows {
		if f.Sink.ID == "php.cassandra.session.execute" {
			t.Errorf("unexpected CQL-injection flow on literal-only call: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
