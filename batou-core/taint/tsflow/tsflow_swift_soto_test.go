package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Swift — Soto (AWS SDK for Swift) query-language injection tests
// =========================================================================
//
// Soto (https://github.com/soto-project/soto) is the production-grade Swift
// SDK for AWS, used by Vapor and other server-side Swift applications.
// Several AWS data services accept a raw query string as the entry point of
// the request input struct:
//
//   1. DynamoDB.executeStatement(_:)            — PartiQL (CWE-943)
//   2. DynamoDB.executeTransaction(_:)          — PartiQL (CWE-943)
//   3. DynamoDB.batchExecuteStatement(_:)       — PartiQL (CWE-943)
//   4. Athena.startQueryExecution(_:)           — Presto SQL (CWE-89)
//   5. RedshiftData.executeStatement(_:)        — Redshift SQL (CWE-89)
//   6. RedshiftData.batchExecuteStatement(_:)   — Redshift SQL (CWE-89)
//   7. TimestreamQuery.query(_:)                — Timestream SQL (CWE-89)
//
// Tainted concatenation or `\(value)` interpolation into the query string
// is query-language injection. The safe pattern is the structured
// `parameters:` (or `executionParameters:`) binding array each service
// provides.

// DynamoDB.executeStatement with tainted PartiQL string interpolation.
func TestSwift_Soto_DynamoDB_ExecuteStatement_Tainted(t *testing.T) {
	code := `
import SotoDynamoDB

func handler(input: String) async throws {
    let dynamoDB = DynamoDB(client: awsClient)
    let result = try await dynamoDB.executeStatement(.init(statement: "SELECT * FROM Users WHERE id = '\(input)'"))
    _ = result
}
`
	flows := Analyze(code, "/app/UsersHandler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected PartiQL injection flow for input -> dynamoDB.executeStatement()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// DynamoDB.executeTransaction with tainted PartiQL inside transactStatements.
func TestSwift_Soto_DynamoDB_ExecuteTransaction_Tainted(t *testing.T) {
	code := `
import SotoDynamoDB

func handler(input: String) async throws {
    let dynamoDB = DynamoDB(client: awsClient)
    let stmt = ParameterizedStatement(statement: "UPDATE t SET v = 'x' WHERE id = '\(input)'")
    try await dynamoDB.executeTransaction(.init(transactStatements: [stmt]))
}
`
	flows := Analyze(code, "/app/TxHandler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected PartiQL injection flow for input -> dynamoDB.executeTransaction()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// DynamoDB.batchExecuteStatement with tainted PartiQL inside statements array.
func TestSwift_Soto_DynamoDB_BatchExecuteStatement_Tainted(t *testing.T) {
	code := `
import SotoDynamoDB

func handler(input: String) async throws {
    let dynamoDB = DynamoDB(client: awsClient)
    let req = BatchStatementRequest(statement: "SELECT * FROM Users WHERE id = '\(input)'")
    try await dynamoDB.batchExecuteStatement(.init(statements: [req]))
}
`
	flows := Analyze(code, "/app/BatchHandler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected PartiQL injection flow for input -> dynamoDB.batchExecuteStatement()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Athena.startQueryExecution with tainted SQL queryString.
func TestSwift_Soto_Athena_StartQueryExecution_Tainted(t *testing.T) {
	code := `
import SotoAthena

func handler(input: String) async throws {
    let athena = Athena(client: awsClient)
    let result = try await athena.startQueryExecution(.init(queryString: "SELECT * FROM logs WHERE user_id = '\(input)'"))
    _ = result
}
`
	flows := Analyze(code, "/app/AthenaHandler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for input -> athena.startQueryExecution()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// RedshiftData.executeStatement with tainted SQL.
func TestSwift_Soto_RedshiftData_ExecuteStatement_Tainted(t *testing.T) {
	code := `
import SotoRedshiftData

func handler(input: String) async throws {
    let redshiftData = RedshiftData(client: awsClient)
    let result = try await redshiftData.executeStatement(.init(clusterIdentifier: "c", database: "db", sql: "SELECT * FROM events WHERE name = '\(input)'"))
    _ = result
}
`
	flows := Analyze(code, "/app/RedshiftHandler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for input -> redshiftData.executeStatement()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// RedshiftData.batchExecuteStatement with tainted SQL element.
func TestSwift_Soto_RedshiftData_BatchExecuteStatement_Tainted(t *testing.T) {
	code := `
import SotoRedshiftData

func handler(input: String) async throws {
    let redshiftData = RedshiftData(client: awsClient)
    try await redshiftData.batchExecuteStatement(.init(clusterIdentifier: "c", database: "db", sqls: ["SELECT * FROM events WHERE name = '\(input)'"]))
}
`
	flows := Analyze(code, "/app/RedshiftBatchHandler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for input -> redshiftData.batchExecuteStatement()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// TimestreamQuery.query with tainted queryString.
func TestSwift_Soto_TimestreamQuery_Query_Tainted(t *testing.T) {
	code := `
import SotoTimestreamQuery

func handler(input: String) async throws {
    let timestreamQuery = TimestreamQuery(client: awsClient)
    let result = try await timestreamQuery.query(.init(queryString: "SELECT * FROM metrics WHERE host = '\(input)'"))
    _ = result
}
`
	flows := Analyze(code, "/app/TimestreamHandler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for input -> timestreamQuery.query()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Safe: tainted value passed via DynamoDB's `parameters:` binding array,
// not interpolated into the `statement:` string. Should not produce a
// swift.soto.dynamodb.* flow.
func TestSwift_Soto_DynamoDB_ParameterizedBinding_Safe(t *testing.T) {
	code := `
import SotoDynamoDB
import Vapor

func handler(req: Request) async throws {
    let id = req.query["id"] ?? ""
    let dynamoDB = DynamoDB(client: awsClient)
    _ = try await dynamoDB.executeStatement(.init(
        parameters: [.s(id)],
        statement: "SELECT * FROM Users WHERE id = ?"
    ))
}
`
	flows := Analyze(code, "/app/SafeUsersHandler.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery &&
			(f.Sink.ID == "swift.soto.dynamodb.executestatement" ||
				f.Sink.ID == "swift.soto.dynamodb.executetransaction" ||
				f.Sink.ID == "swift.soto.dynamodb.batchexecutestatement") {
			t.Errorf("expected NO swift.soto.dynamodb.* flow when tainted value only reaches `parameters:` binding, got sink %s", f.Sink.ID)
		}
	}
}
