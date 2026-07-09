package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// C++ cloud data warehouse SQL injection tests (CWE-89/943)
//
// Covers:
//   * google-cloud-cpp Spanner — spanner::SqlStatement / spanner::Client
//     ExecuteQuery / ExecuteDml / ExecutePartitionedDml
//   * AWS SDK for C++ — Athena StartQueryExecutionRequest::SetQueryString /
//     WithQueryString, DynamoDB ExecuteStatementRequest::SetStatement /
//     WithStatement (PartiQL), Redshift Data API ExecuteStatementRequest::
//     SetSql / WithSql
//
// All of these APIs accept the raw SQL/PartiQL as the first arg of a setter
// (or the constructor for spanner::SqlStatement). Concatenating tainted
// input into that string is SQL/PartiQL injection because none of the
// underlying services parameter-bind values from the same string.
// =========================================================================

// ── google-cloud-cpp Spanner ─────────────────────────────────────────────

func TestCPP_Spanner_SqlStatement_Injection(t *testing.T) {
	code := `
#include "google/cloud/spanner/client.h"
#include <string>

namespace spanner = google::cloud::spanner;

void run(const char* argv[]) {
    spanner::Client client(spanner::MakeConnection({}));
    std::string user = argv[1];
    std::string sql = "SELECT id FROM users WHERE name = '" + user + "'";
    auto stmt = spanner::SqlStatement(sql);
    auto rows = client.ExecuteQuery(stmt);
}
`
	flows := Analyze(code, "/app/spanner_sqlstmt.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for argv -> spanner::SqlStatement")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Spanner_ExecuteQuery_Injection(t *testing.T) {
	code := `
#include "google/cloud/spanner/client.h"
#include <string>

namespace spanner = google::cloud::spanner;

void run(spanner::Client& client, const char* argv[]) {
    std::string input = argv[1];
    auto rows = client.ExecuteQuery(input);
}
`
	flows := Analyze(code, "/app/spanner_executequery.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for argv -> client.ExecuteQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Spanner_ExecuteDml_Injection(t *testing.T) {
	code := `
#include "google/cloud/spanner/client.h"
#include <string>

namespace spanner = google::cloud::spanner;

void run(spanner::Client& client, const char* argv[]) {
    std::string input = argv[1];
    std::string sql = "DELETE FROM accounts WHERE owner = '" + input + "'";
    auto out = client.ExecuteDml(sql);
}
`
	flows := Analyze(code, "/app/spanner_executedml.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for argv -> client.ExecuteDml")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Spanner_ExecutePartitionedDml_Injection(t *testing.T) {
	code := `
#include "google/cloud/spanner/client.h"
#include <string>

namespace spanner = google::cloud::spanner;

void run(spanner::Client& client, const char* argv[]) {
    std::string input = argv[1];
    std::string sql = "UPDATE events SET seen = true WHERE region = '" + input + "'";
    auto out = client.ExecutePartitionedDml(sql);
}
`
	flows := Analyze(code, "/app/spanner_partitioneddml.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for argv -> client.ExecutePartitionedDml")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ── AWS SDK for C++ — Athena ─────────────────────────────────────────────

func TestCPP_AWS_Athena_SetQueryString_Injection(t *testing.T) {
	code := `
#include <aws/athena/AthenaClient.h>
#include <aws/athena/model/StartQueryExecutionRequest.h>
#include <string>

void run(const char* argv[]) {
    Aws::Athena::Model::StartQueryExecutionRequest req;
    std::string input = argv[1];
    std::string sql = "SELECT count(*) FROM logs WHERE region = '" + input + "'";
    req.SetQueryString(sql);
    Aws::Athena::AthenaClient client;
    auto out = client.StartQueryExecution(req);
}
`
	flows := Analyze(code, "/app/athena_setquery.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for argv -> req.SetQueryString")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_AWS_Athena_WithQueryString_Injection(t *testing.T) {
	code := `
#include <aws/athena/AthenaClient.h>
#include <aws/athena/model/StartQueryExecutionRequest.h>
#include <string>

void run(const char* argv[]) {
    std::string input = argv[1];
    std::string sql = "SELECT * FROM events WHERE host = '" + input + "'";
    Aws::Athena::Model::StartQueryExecutionRequest req;
    req.WithQueryString(sql);
    Aws::Athena::AthenaClient client;
    client.StartQueryExecution(req);
}
`
	flows := Analyze(code, "/app/athena_withquery.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for argv -> req.WithQueryString")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ── AWS SDK for C++ — DynamoDB PartiQL ───────────────────────────────────

func TestCPP_AWS_DynamoDB_SetStatement_Injection(t *testing.T) {
	code := `
#include <aws/dynamodb/DynamoDBClient.h>
#include <aws/dynamodb/model/ExecuteStatementRequest.h>
#include <string>

void run(const char* argv[]) {
    std::string input = argv[1];
    std::string partiql = "SELECT * FROM Users WHERE id = '" + input + "'";
    Aws::DynamoDB::Model::ExecuteStatementRequest req;
    req.SetStatement(partiql);
    Aws::DynamoDB::DynamoDBClient client;
    client.ExecuteStatement(req);
}
`
	flows := Analyze(code, "/app/ddb_setstatement.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected PartiQL injection flow for argv -> req.SetStatement")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_AWS_DynamoDB_WithStatement_Injection(t *testing.T) {
	code := `
#include <aws/dynamodb/DynamoDBClient.h>
#include <aws/dynamodb/model/ExecuteStatementRequest.h>
#include <string>

void run(const char* argv[]) {
    std::string input = argv[1];
    std::string partiql = "DELETE FROM Items WHERE owner = '" + input + "'";
    Aws::DynamoDB::Model::ExecuteStatementRequest req;
    req.WithStatement(partiql);
    Aws::DynamoDB::DynamoDBClient client;
    client.ExecuteStatement(req);
}
`
	flows := Analyze(code, "/app/ddb_withstatement.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected PartiQL injection flow for argv -> req.WithStatement")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ── AWS SDK for C++ — Redshift Data API ──────────────────────────────────

func TestCPP_AWS_RedshiftData_SetSql_Injection(t *testing.T) {
	code := `
#include <aws/redshift-data/RedshiftDataAPIServiceClient.h>
#include <aws/redshift-data/model/ExecuteStatementRequest.h>
#include <string>

void run(const char* argv[]) {
    std::string input = argv[1];
    std::string sql = "SELECT amount FROM ledger WHERE account = '" + input + "'";
    Aws::RedshiftDataAPIService::Model::ExecuteStatementRequest req;
    req.SetSql(sql);
    Aws::RedshiftDataAPIService::RedshiftDataAPIServiceClient client;
    client.ExecuteStatement(req);
}
`
	flows := Analyze(code, "/app/redshiftdata_setsql.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for argv -> req.SetSql")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_AWS_RedshiftData_WithSql_Injection(t *testing.T) {
	code := `
#include <aws/redshift-data/RedshiftDataAPIServiceClient.h>
#include <aws/redshift-data/model/ExecuteStatementRequest.h>
#include <string>

void run(const char* argv[]) {
    std::string input = argv[1];
    std::string sql = "DELETE FROM ledger WHERE account = '" + input + "'";
    Aws::RedshiftDataAPIService::Model::ExecuteStatementRequest req;
    req.WithSql(sql);
    Aws::RedshiftDataAPIService::RedshiftDataAPIServiceClient client;
    client.ExecuteStatement(req);
}
`
	flows := Analyze(code, "/app/redshiftdata_withsql.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for argv -> req.WithSql")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Negative tests — over-broadness regression checks
// =========================================================================

// Hardcoded SQL with no tainted input should NOT fire.
func TestCPP_Spanner_HardcodedSQL_Safe(t *testing.T) {
	code := `
#include "google/cloud/spanner/client.h"
#include <string>

namespace spanner = google::cloud::spanner;

void run(spanner::Client& client) {
    auto stmt = spanner::SqlStatement("SELECT 1");
    auto rows = client.ExecuteQuery(stmt);
}
`
	flows := Analyze(code, "/app/spanner_safe_const.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("expected NO SQL injection flow for hardcoded SQL; got %s -> %s (conf: %.2f)",
				f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Hardcoded PartiQL on DynamoDB ExecuteStatement should NOT fire either.
func TestCPP_AWS_DynamoDB_HardcodedPartiQL_Safe(t *testing.T) {
	code := `
#include <aws/dynamodb/DynamoDBClient.h>
#include <aws/dynamodb/model/ExecuteStatementRequest.h>

void run() {
    Aws::DynamoDB::Model::ExecuteStatementRequest req;
    req.SetStatement("SELECT * FROM Users WHERE id = ?");
    Aws::DynamoDB::DynamoDBClient client;
    client.ExecuteStatement(req);
}
`
	flows := Analyze(code, "/app/ddb_safe_const.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("expected NO PartiQL injection flow for hardcoded statement; got %s -> %s (conf: %.2f)",
				f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
