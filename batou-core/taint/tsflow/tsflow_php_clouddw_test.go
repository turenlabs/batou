package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// PHP cloud data warehouse SQL/PartiQL injection tests (CWE-89, CWE-943)
//
// Covers:
//   - google/cloud-bigquery: BigQueryClient::query / queryConfig
//   - google/cloud-spanner: Database / Transaction execute / executeUpdate
//   - AWS SDK PHP V3: Athena, Redshift Data, Timestream Query, DynamoDB PartiQL
//
// Each AWS SDK PHP call passes an associative array at arg 0 with a tainted
// SQL/PartiQL value under the canonical key (`QueryString`, `Sql`, `Sqls`,
// `Statement`). tsflow's nodeIsTainted recurses through array_creation_expression
// + array_element_initializer, so the sink fires on any tainted value within
// the array.
// =========================================================================

// --- google/cloud-bigquery: $bigQuery->query($sql) ---

func TestPHP_BigQuery_Client_Query(t *testing.T) {
	code := `<?php
function fetch_users($bigQuery) {
    $userId = $_GET['user_id'];
    $sql = "SELECT * FROM dataset.users WHERE id = " . $userId;
    $job = $bigQuery->query($sql);
    return $bigQuery->runQuery($job);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL-injection flow for $_GET -> $bigQuery->query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- google/cloud-bigquery: $bigQuery->queryConfig($sql) ---

func TestPHP_BigQuery_Client_QueryConfig(t *testing.T) {
	code := `<?php
function build_job($bigQuery) {
    $term = $_POST['term'];
    $sql = "SELECT * FROM logs WHERE message LIKE '%" . $term . "%'";
    return $bigQuery->queryConfig($sql);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL-injection flow for $_POST -> $bigQuery->queryConfig")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- google/cloud-spanner: $database->execute($sql) ---

func TestPHP_Spanner_Database_Execute(t *testing.T) {
	code := `<?php
function fetch_singer($database) {
    $name = $_GET['name'];
    $sql = "SELECT SingerId FROM Singers WHERE FirstName = '" . $name . "'";
    $results = $database->execute($sql);
    return $results->rows();
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL-injection flow for $_GET -> $database->execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- google/cloud-spanner: $database->executeUpdate($sql) (DML) ---

func TestPHP_Spanner_Database_ExecuteUpdate(t *testing.T) {
	code := `<?php
function delete_singer($database) {
    $singerId = $_REQUEST['id'];
    $sql = "DELETE FROM Singers WHERE SingerId = " . $singerId;
    return $database->executeUpdate($sql);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected DML-injection flow for $_REQUEST -> $database->executeUpdate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- google/cloud-spanner: $transaction->execute($sql) inside runTransaction ---

func TestPHP_Spanner_Transaction_Execute(t *testing.T) {
	code := `<?php
function read_in_tx($transaction) {
    $albumTitle = $_GET['title'];
    $sql = "SELECT AlbumId FROM Albums WHERE AlbumTitle = '" . $albumTitle . "'";
    return $transaction->execute($sql);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL-injection flow for $_GET -> $transaction->execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- google/cloud-spanner: $transaction->executeUpdate($sql) DML in tx ---

func TestPHP_Spanner_Transaction_ExecuteUpdate(t *testing.T) {
	code := `<?php
function update_in_tx($transaction) {
    $newName = $_POST['name'];
    $sql = "UPDATE Singers SET FirstName = '" . $newName . "' WHERE SingerId = 1";
    return $transaction->executeUpdate($sql);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected DML-injection flow for $_POST -> $transaction->executeUpdate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- AWS Athena: $athena->startQueryExecution(['QueryString' => $sql]) ---

func TestPHP_AWS_Athena_StartQueryExecution(t *testing.T) {
	code := `<?php
function run_athena_query($athena) {
    $table = $_GET['table'];
    $sql = "SELECT * FROM " . $table . " LIMIT 100";
    return $athena->startQueryExecution([
        'QueryString' => $sql,
        'WorkGroup' => 'primary',
        'ResultConfiguration' => ['OutputLocation' => 's3://results/'],
    ]);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL-injection flow for $_GET -> $athena->startQueryExecution")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- AWS Redshift Data: $redshiftData->executeStatement(['Sql' => $sql]) ---

func TestPHP_AWS_RedshiftData_ExecuteStatement(t *testing.T) {
	code := `<?php
function run_redshift_stmt($redshiftData) {
    $userInput = $_POST['filter'];
    $sql = "SELECT * FROM events WHERE category = '" . $userInput . "'";
    return $redshiftData->executeStatement([
        'ClusterIdentifier' => 'my-cluster',
        'Database' => 'analytics',
        'Sql' => $sql,
    ]);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL-injection flow for $_POST -> $redshiftData->executeStatement")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- AWS Redshift Data: batchExecuteStatement(['Sqls' => [$sql, ...]]) ---

func TestPHP_AWS_RedshiftData_BatchExecuteStatement(t *testing.T) {
	code := `<?php
function run_redshift_batch($redshiftData) {
    $sortField = $_GET['sort'];
    $sqlA = "SELECT * FROM users ORDER BY " . $sortField;
    return $redshiftData->batchExecuteStatement([
        'ClusterIdentifier' => 'my-cluster',
        'Database' => 'analytics',
        'Sqls' => [$sqlA, "SELECT COUNT(*) FROM users"],
    ]);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL-injection flow for $_GET -> $redshiftData->batchExecuteStatement")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- AWS Timestream Query: $timestream->query(['QueryString' => $sql]) ---

func TestPHP_AWS_TimestreamQuery_Query(t *testing.T) {
	code := `<?php
function timestream_query($timestreamQuery) {
    $metric = $_GET['metric'];
    $sql = "SELECT * FROM \"db\".\"events\" WHERE measure_name = '" . $metric . "'";
    return $timestreamQuery->query([
        'QueryString' => $sql,
        'MaxRows' => 1000,
    ]);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL-injection flow for $_GET -> $timestreamQuery->query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- AWS DynamoDB PartiQL: $dynamoDb->executeStatement(['Statement' => $sql]) ---

func TestPHP_AWS_DynamoDB_ExecuteStatement(t *testing.T) {
	code := `<?php
function run_partiql($dynamoDb) {
    $userId = $_REQUEST['user_id'];
    $partiql = "SELECT * FROM \"Users\" WHERE id = '" . $userId . "'";
    return $dynamoDb->executeStatement([
        'Statement' => $partiql,
    ]);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected PartiQL-injection flow for $_REQUEST -> $dynamoDb->executeStatement")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Negative: literal SQL with no user input — no flow expected ---
//
// Note: avoid `runQuery(`, `Query(`, etc. in the body — the tsflow web-handler
// heuristic substring-matches `Query(` (used by Hono/Pydantic decorators) and
// would otherwise seed every parameter as user-controlled.

func TestPHP_BigQuery_Safe_LiteralQuery(t *testing.T) {
	code := `<?php
function list_users_safe_bq($bigQuery) {
    return $bigQuery->query('SELECT id FROM dataset.users LIMIT 10');
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	for _, f := range flows {
		switch f.Sink.ID {
		case "php.bigquery.client.query", "php.bigquery.client.queryconfig":
			t.Errorf("unexpected flow on literal-only call: %s -> %s (sink=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Negative: Athena with all-literal QueryString — no flow expected ---

func TestPHP_AWS_Athena_Safe_LiteralQueryString(t *testing.T) {
	code := `<?php
function safe_athena($athena) {
    return $athena->startQueryExecution([
        'QueryString' => 'SELECT count(*) FROM logs',
        'WorkGroup' => 'primary',
    ]);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	for _, f := range flows {
		if f.Sink.ID == "php.aws.athena.startqueryexecution" {
			t.Errorf("unexpected flow on literal-only Athena call: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
