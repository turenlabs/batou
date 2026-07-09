package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Swift Soto AWS storage/queue reads — second-order taint tests.
//
// Soto (the AWS SDK for server-side Swift) already had injection SINKS for
// DynamoDB.executeStatement / Athena / RedshiftData / TimestreamQuery, but no
// SOURCES. Data an attacker writes to S3, DynamoDB or SQS and the app reads
// back is attacker-controlled; reaching a SQL/command/eval sink with it is a
// second-order injection. Mirrors the multi-language AWS read-source additions
// (java.aws.* PR #1034, kotlin.aws.*, php Aws\DynamoDb PR #1033, ruby
// aws-sdk-dynamodb PR #1032).
//
// Each test plumbs a Soto read into SQLite.swift's Connection.execute
// (swift.sqliteswift.execute, ObjectType "Connection" matched against receiver
// "db" via the connection heuristic in matcher.go). Result values are
// interpolated directly into the SQL string (\(value)) — the same propagation
// shape the swift.redistack.* read-source tests use. SQL/Query/HTTP-verb
// keywords are intentionally kept out of the function bodies so isWebHandlerFunc
// does not auto-seed the parameters as tainted (which would mask whether the
// new source itself fires). The Soto client and the db handle are passed as
// plain parameters for that reason.

// --- S3 getObject ------------------------------------------------------

func TestSwift_Soto_S3GetObject_SQLi(t *testing.T) {
	code := `
import SotoS3
import SQLite

func replayObject(s3: S3, db: Connection) throws {
    let stored = s3.getObject(req)
    let sql = "SELECT * FROM items WHERE name = '\(stored)'"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/ReplayObject.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for s3.getObject -> db.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- DynamoDB getItem --------------------------------------------------

func TestSwift_Soto_DynamoGetItem_SQLi(t *testing.T) {
	code := `
import SotoDynamoDB
import SQLite

func loadItem(dynamoDB: DynamoDB, db: Connection) throws {
    let item = dynamoDB.getItem(req)
    let sql = "SELECT * FROM audit WHERE val = '\(item)'"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/LoadItem.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for dynamoDB.getItem -> db.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- DynamoDB query ----------------------------------------------------

func TestSwift_Soto_DynamoQuery_SQLi(t *testing.T) {
	code := `
import SotoDynamoDB
import SQLite

func runLookup(dynamoDB: DynamoDB, db: Connection) throws {
    let rows = dynamoDB.query(req)
    let sql = "SELECT * FROM events WHERE id IN ('\(rows)')"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/RunLookup.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for dynamoDB.query -> db.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- DynamoDB scan -----------------------------------------------------

func TestSwift_Soto_DynamoScan_SQLi(t *testing.T) {
	code := `
import SotoDynamoDB
import SQLite

func dumpAll(dynamoDB: DynamoDB, db: Connection) throws {
    let all = dynamoDB.scan(req)
    let sql = "SELECT * FROM cache WHERE k = '\(all)'"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/DumpAll.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for dynamoDB.scan -> db.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- DynamoDB batchGetItem ---------------------------------------------

func TestSwift_Soto_DynamoBatchGetItem_SQLi(t *testing.T) {
	code := `
import SotoDynamoDB
import SQLite

func loadBatch(dynamoDB: DynamoDB, db: Connection) throws {
    let batch = dynamoDB.batchGetItem(req)
    let sql = "SELECT * FROM records WHERE tag = '\(batch)'"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/LoadBatch.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for dynamoDB.batchGetItem -> db.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- SQS receiveMessage ------------------------------------------------

func TestSwift_Soto_SQSReceiveMessage_SQLi(t *testing.T) {
	code := `
import SotoSQS
import SQLite

func consume(sqs: SQS, db: Connection) throws {
    let msg = sqs.receiveMessage(req)
    let sql = "SELECT * FROM jobs WHERE payload = '\(msg)'"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/Consume.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for sqs.receiveMessage -> db.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Negative control --------------------------------------------------
// A constant-only SQL string with no Soto read must NOT produce a flow.

func TestSwift_Soto_ConstantNoFlow(t *testing.T) {
	code := `
import SotoDynamoDB
import SQLite

func staticLookup(dynamoDB: DynamoDB, db: Connection) throws {
    let sql = "SELECT * FROM items WHERE name = 'fixed'"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/StaticLookup.swift", rules.LangSwift)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did not expect a SQL flow for a constant query with no Soto read")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}
