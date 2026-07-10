package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// PHP laudis/neo4j-php-client + graphaware/neo4j-php-client (legacy)
// Cypher-injection tests (CWE-943).
//
// Mirrors py.neo4j.*, kotlin.neo4j.*, csharp.neo4j.*, rust.neo4rs.* coverage
// for the PHP ecosystem. Sinks scope by ObjectType (Session/Tx/Client/
// Statement) so generic ->run() calls in unrelated frameworks do not FP.
// =========================================================================

// --- ClientInterface::run — laudis auto-commit ---

func TestPHP_Neo4j_Client_Run(t *testing.T) {
	code := `<?php
function lookup_user($client) {
    $name = $_GET['name'];
    $cypher = "MATCH (u:User) WHERE u.name = '" . $name . "' RETURN u";
    return $client->run($cypher);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Cypher-injection flow for $_GET -> $client->run")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- SessionInterface::run ---

func TestPHP_Neo4j_Session_Run(t *testing.T) {
	code := `<?php
function fetch_node($session) {
    $label = $_POST['label'];
    $cypher = "MATCH (n:" . $label . ") RETURN n LIMIT 10";
    return $session->run($cypher);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Cypher-injection flow for $_POST -> $session->run")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- TransactionInterface::run inside a managed transaction ---

func TestPHP_Neo4j_Transaction_Run(t *testing.T) {
	code := `<?php
function delete_in_tx($tx) {
    $id = $_REQUEST['id'];
    $cypher = "MATCH (n) WHERE id(n) = " . $id . " DETACH DELETE n";
    return $tx->run($cypher);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Cypher-injection flow for $_REQUEST -> $tx->run")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Statement::create value-object factory ---

func TestPHP_Neo4j_Statement_Create(t *testing.T) {
	code := `<?php
use Laudis\Neo4j\Databags\Statement;

function build_stmt($client) {
    $email = $_POST['email'];
    $cypher = "MATCH (u:User {email: '" . $email . "'}) RETURN u";
    $stmt = Statement::create($cypher);
    return $client->runStatement($stmt);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Cypher-injection flow for $_POST -> Statement::create")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- graphaware-legacy ClientInterface::sendCypherQuery ---

func TestPHP_Neo4j_Graphaware_SendCypherQuery(t *testing.T) {
	code := `<?php
function legacy_query($client) {
    $tag = $_GET['tag'];
    $cypher = "MATCH (p:Post) WHERE p.tag = '" . $tag . "' RETURN p";
    return $client->sendCypherQuery($cypher);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Cypher-injection flow for $_GET -> $client->sendCypherQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Safe: literal Cypher with no user input — no flow expected ---

func TestPHP_Neo4j_Safe_LiteralQuery(t *testing.T) {
	code := `<?php
function list_users($client) {
    return $client->run('MATCH (u:User) RETURN u LIMIT 10');
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	for _, f := range flows {
		if f.Sink.ID == "php.neo4j.client.run" {
			t.Errorf("unexpected Cypher-injection flow on literal-only call: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
