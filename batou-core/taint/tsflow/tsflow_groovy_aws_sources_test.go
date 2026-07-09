package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Groovy AWS SDK (S3 / SQS / DynamoDB) read sources — second-order taint.
//
// Groovy/Grails/Micronaut/Jenkins apps run on the JVM and use the exact same
// AWS SDK for Java as Java does. Java's catalog already models S3, SQS, and
// DynamoDB reads as second-order taint sources (java.aws.*,
// java.dynamodb.client.*) but Groovy had none — attacker-influenced bytes
// written to a bucket/queue/table on one request and read back on a later
// request did not propagate taint into downstream sinks. These mirror the
// Java entries (same ObjectType/MethodName).
//
// Receivers used in the fixtures (`s3`, `sqs`, `dynamoDb`) are prefixes of
// the ObjectType last segment ("s3client"/"sqsclient"/"dynamodbclient"), so
// the matcher's prefix-abbreviation heuristic (matcher.go) anchors them.
// As with the existing Groovy Cassandra/Jedis/JDBC second-order tests, the
// dynamically-typed return value propagates taint through direct string
// concatenation (implicit toString() goes through the `+` operator path).
// =========================================================================

func TestGroovy_AWSReadSources_Registered(t *testing.T) {
	want := map[string]taint.SourceCategory{
		"groovy.aws.s3.getobject":             taint.SrcExternal,
		"groovy.aws.s3.getobjectasbytes":      taint.SrcExternal,
		"groovy.aws.sqs.receivemessage":       taint.SrcExternal,
		"groovy.dynamodb.client.getitem":      taint.SrcDatabase,
		"groovy.dynamodb.client.query":        taint.SrcDatabase,
		"groovy.dynamodb.client.scan":         taint.SrcDatabase,
		"groovy.dynamodb.client.batchgetitem": taint.SrcDatabase,
	}
	sources := taint.SourcesForLanguage(rules.LangGroovy)
	for id, cat := range want {
		found := false
		for _, s := range sources {
			if s.ID == id {
				if s.Category != cat {
					t.Errorf("source %s: expected category %v, got %v", id, cat, s.Category)
				}
				found = true
				break
			}
		}
		if !found {
			t.Errorf("source %s not found in Groovy catalog", id)
		}
	}
}

// ---------- S3 getObject → SQL injection (CWE-89) ----------

func TestGroovy_AWS_S3GetObject_ToSQLInjection(t *testing.T) {
	code := `
def render() {
    def obj = s3.getObject(getReq)
    sql.execute("SELECT * FROM events WHERE name = '" + obj + "'")
}
`
	flows := Analyze(code, "/app/S3Repo.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for S3Client.getObject -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// ---------- S3 getObjectAsBytes → command injection (CWE-78) ----------

func TestGroovy_AWS_S3GetObjectAsBytes_ToCommand(t *testing.T) {
	code := `
def runJob() {
    def bytes = s3.getObjectAsBytes(getReq)
    Runtime.getRuntime().exec(bytes.toString())
}
`
	flows := Analyze(code, "/app/S3Runner.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for S3Client.getObjectAsBytes -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// ---------- SQS receiveMessage → SQL injection (CWE-89) ----------

func TestGroovy_AWS_SqsReceiveMessage_ToSQLInjection(t *testing.T) {
	code := `
def consume() {
    def resp = sqs.receiveMessage(rmReq)
    sql.execute("INSERT INTO log(msg) VALUES ('" + resp + "')")
}
`
	flows := Analyze(code, "/app/QueueConsumer.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for SqsClient.receiveMessage -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// ---------- DynamoDB getItem → SQL injection (CWE-89) ----------

func TestGroovy_AWS_DynamoGetItem_ToSQLInjection(t *testing.T) {
	code := `
def lookup() {
    def item = dynamoDb.getItem(giReq)
    sql.execute("SELECT * FROM users WHERE name = '" + item + "'")
}
`
	flows := Analyze(code, "/app/DynamoRepo.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for DynamoDbClient.getItem -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// ---------- DynamoDB query → command injection (CWE-78) ----------

func TestGroovy_AWS_DynamoQuery_ToCommand(t *testing.T) {
	code := `
def search() {
    def resp = dynamoDb.query(qReq)
    Runtime.getRuntime().exec(resp.toString())
}
`
	flows := Analyze(code, "/app/DynamoSearch.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for DynamoDbClient.query -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// ---------- DynamoDB scan → SQL injection (CWE-89) ----------

func TestGroovy_AWS_DynamoScan_ToSQLInjection(t *testing.T) {
	code := `
def listAll() {
    def resp = dynamoDb.scan(scanReq)
    sql.execute("SELECT * FROM events WHERE tag = '" + resp + "'")
}
`
	flows := Analyze(code, "/app/DynamoScan.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for DynamoDbClient.scan -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// ---------- DynamoDB batchGetItem → SQL injection (CWE-89) ----------

func TestGroovy_AWS_DynamoBatchGetItem_ToSQLInjection(t *testing.T) {
	code := `
def batchLookup() {
    def resp = dynamoDb.batchGetItem(bgiReq)
    sql.execute("SELECT * FROM users WHERE name = '" + resp + "'")
}
`
	flows := Analyze(code, "/app/DynamoBatch.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for DynamoDbClient.batchGetItem -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// ---------- Negative control: constant value, no AWS source → no flow ----------

func TestGroovy_AWS_ConstantValue_NoFlow(t *testing.T) {
	code := `
def render() {
    def name = "static-constant"
    sql.execute("SELECT * FROM events WHERE name = '" + name + "'")
}
`
	flows := Analyze(code, "/app/Constant.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did not expect a SQL flow for a constant (non-source) value")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}
