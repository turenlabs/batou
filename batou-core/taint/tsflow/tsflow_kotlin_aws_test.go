package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// AWS SDK inbound message sources for Kotlin (CWE-20 / CWE-915).
// Covers AWS SDK Java v1 (com.amazonaws.*), Java v2 (software.amazon.awssdk.*),
// and AWS SDK for Kotlin (aws.sdk.kotlin.*). Inbound payloads from S3/SQS/
// DynamoDB/Kinesis carry attacker-controlled data via uploads, queue producers,
// and stream writers.

// ---------- S3 GetObject (CWE-89 SQL injection via stored object) ----------

func TestKotlin_AWS_S3_GetObject_SQLInjection(t *testing.T) {
	code := `
import software.amazon.awssdk.services.s3.S3Client
import software.amazon.awssdk.services.s3.model.GetObjectRequest
import java.sql.Connection

class Loader(private val s3: S3Client, private val dbConn: Connection) {
    fun load(key: String) {
        val req = GetObjectRequest.builder().bucket("data").key(key).build()
        val payload = s3.getObject(req)
        val stmt = dbConn.createStatement()
        stmt.executeQuery("SELECT * FROM cache WHERE blob = '" + payload + "'")
    }
}
`
	flows := Analyze(code, "/app/Loader.kt", rules.LangKotlin)
	if !hasFlowFromSource(flows, "kotlin.aws.s3.client.getobject", taint.SnkSQLQuery) {
		t.Errorf("expected SQL injection flow from S3Client.getObject -> executeQuery; flows=%+v", flows)
	}
}

// ---------- S3 v1 S3Object.getObjectContent (CWE-78 command injection) ----------

func TestKotlin_AWS_S3_ObjectContent_CommandInjection(t *testing.T) {
	code := `
import com.amazonaws.services.s3.AmazonS3
import com.amazonaws.services.s3.model.S3Object

fun fetchAndRun(client: AmazonS3, key: String) {
    val s3Object: S3Object = client.getObject("bucket", key)
    val content = s3Object.getObjectContent()
    Runtime.getRuntime().exec(content.toString())
}
`
	flows := Analyze(code, "/app/Fetch.kt", rules.LangKotlin)
	if !hasFlowFromSource(flows, "kotlin.aws.s3.s3object.objectcontent", taint.SnkCommand) {
		t.Errorf("expected command injection flow from S3Object.getObjectContent -> Runtime.exec; flows=%+v", flows)
	}
}

// ---------- SQS ReceiveMessage (CWE-89) ----------

func TestKotlin_AWS_SQS_ReceiveMessage_SQLInjection(t *testing.T) {
	code := `
import software.amazon.awssdk.services.sqs.SqsClient
import software.amazon.awssdk.services.sqs.model.ReceiveMessageRequest
import java.sql.Connection

class Worker(private val sqs: SqsClient, private val dbConn: Connection) {
    fun pull() {
        val req = ReceiveMessageRequest.builder().queueUrl("q").build()
        val response = sqs.receiveMessage(req)
        val stmt = dbConn.createStatement()
        stmt.executeQuery("INSERT INTO log VALUES ('" + response + "')")
    }
}
`
	flows := Analyze(code, "/app/Worker.kt", rules.LangKotlin)
	if !hasFlowFromSource(flows, "kotlin.aws.sqs.client.receivemessage", taint.SnkSQLQuery) {
		t.Errorf("expected SQL injection flow from SqsClient.receiveMessage -> executeQuery; flows=%+v", flows)
	}
}

// ---------- SQS Message.body() v2 (CWE-78) ----------

func TestKotlin_AWS_SQS_MessageBody_CommandInjection(t *testing.T) {
	code := `
import software.amazon.awssdk.services.sqs.model.Message

fun process(message: Message) {
    val payload = message.body()
    Runtime.getRuntime().exec(payload)
}
`
	flows := Analyze(code, "/app/Process.kt", rules.LangKotlin)
	if !hasFlowFromSource(flows, "kotlin.aws.sqs.message.body", taint.SnkCommand) {
		t.Errorf("expected command injection flow from Message.body -> Runtime.exec; flows=%+v", flows)
	}
}

// ---------- DynamoDB GetItem (CWE-78) ----------

func TestKotlin_AWS_DynamoDB_GetItem_CommandInjection(t *testing.T) {
	code := `
import software.amazon.awssdk.services.dynamodb.DynamoDbClient
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest

class Store(private val dynamoDb: DynamoDbClient) {
    fun lookup(input: String) {
        val req = GetItemRequest.builder().tableName("t").build()
        val response = dynamoDb.getItem(req)
        Runtime.getRuntime().exec(response.toString())
    }
}
`
	flows := Analyze(code, "/app/Store.kt", rules.LangKotlin)
	if !hasFlowFromSource(flows, "kotlin.aws.dynamodb.client.getitem", taint.SnkCommand) {
		t.Errorf("expected command injection flow from DynamoDbClient.getItem -> Runtime.exec; flows=%+v", flows)
	}
}

// ---------- DynamoDB Query (CWE-89) ----------

func TestKotlin_AWS_DynamoDB_Query_SQLInjection(t *testing.T) {
	code := `
import software.amazon.awssdk.services.dynamodb.DynamoDbClient
import software.amazon.awssdk.services.dynamodb.model.QueryRequest
import java.sql.Connection

class Repo(private val dynamoDb: DynamoDbClient, private val dbConn: Connection) {
    fun mirror() {
        val req = QueryRequest.builder().tableName("u").build()
        val response = dynamoDb.query(req)
        val stmt = dbConn.createStatement()
        stmt.executeQuery("INSERT INTO mirror VALUES ('" + response + "')")
    }
}
`
	flows := Analyze(code, "/app/Repo.kt", rules.LangKotlin)
	if !hasFlowFromSource(flows, "kotlin.aws.dynamodb.client.query", taint.SnkSQLQuery) {
		t.Errorf("expected SQL injection flow from DynamoDbClient.query -> executeQuery; flows=%+v", flows)
	}
}

// ---------- DynamoDB Scan (CWE-78) ----------

func TestKotlin_AWS_DynamoDB_Scan_CommandInjection(t *testing.T) {
	code := `
import software.amazon.awssdk.services.dynamodb.DynamoDbClient
import software.amazon.awssdk.services.dynamodb.model.ScanRequest

class Reader(private val dynamoDb: DynamoDbClient) {
    fun walk() {
        val req = ScanRequest.builder().tableName("t").build()
        val response = dynamoDb.scan(req)
        Runtime.getRuntime().exec(response.toString())
    }
}
`
	flows := Analyze(code, "/app/Reader.kt", rules.LangKotlin)
	if !hasFlowFromSource(flows, "kotlin.aws.dynamodb.client.scan", taint.SnkCommand) {
		t.Errorf("expected command injection flow from DynamoDbClient.scan -> Runtime.exec; flows=%+v", flows)
	}
}

// ---------- DynamoDB BatchGetItem (CWE-89) ----------

func TestKotlin_AWS_DynamoDB_BatchGetItem_SQLInjection(t *testing.T) {
	code := `
import software.amazon.awssdk.services.dynamodb.DynamoDbClient
import software.amazon.awssdk.services.dynamodb.model.BatchGetItemRequest
import java.sql.Connection

class Sync(private val dynamoDb: DynamoDbClient, private val dbConn: Connection) {
    fun fan() {
        val req = BatchGetItemRequest.builder().build()
        val response = dynamoDb.batchGetItem(req)
        val stmt = dbConn.createStatement()
        stmt.executeQuery("UPDATE cache SET v = '" + response + "'")
    }
}
`
	flows := Analyze(code, "/app/Sync.kt", rules.LangKotlin)
	if !hasFlowFromSource(flows, "kotlin.aws.dynamodb.client.batchgetitem", taint.SnkSQLQuery) {
		t.Errorf("expected SQL injection flow from DynamoDbClient.batchGetItem -> executeQuery; flows=%+v", flows)
	}
}

// ---------- Kinesis Record.data() (CWE-78) ----------

func TestKotlin_AWS_Kinesis_RecordData_CommandInjection(t *testing.T) {
	code := `
import software.amazon.awssdk.services.kinesis.model.Record

fun consume(record: Record) {
    val payload = record.data()
    Runtime.getRuntime().exec(payload.asUtf8String())
}
`
	flows := Analyze(code, "/app/Consume.kt", rules.LangKotlin)
	if !hasFlowFromSource(flows, "kotlin.aws.kinesis.record.data", taint.SnkCommand) {
		t.Errorf("expected command injection flow from Kinesis Record.data -> Runtime.exec; flows=%+v", flows)
	}
}

// ---------- Negative test: constant SQL — no flow expected ----------

func TestKotlin_AWS_S3_ConstantSQL_NoFlow(t *testing.T) {
	code := `
import software.amazon.awssdk.services.s3.S3Client
import java.sql.Connection

class Constant(private val s3: S3Client, private val dbConn: Connection) {
    fun hardcoded() {
        val stmt = dbConn.createStatement()
        stmt.executeQuery("SELECT * FROM users WHERE id = 42")
    }
}
`
	flows := Analyze(code, "/app/Constant.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Source.ID == "kotlin.aws.s3.client.getobject" {
			t.Errorf("unexpected flow from S3Client.getObject when sink had no source: %+v", f)
		}
	}
}

// hasFlowFromSource asserts a flow exists with the given source ID and sink category.
func hasFlowFromSource(flows []taint.TaintFlow, sourceID string, sinkCat taint.SinkCategory) bool {
	for _, f := range flows {
		if f.Source.ID == sourceID && f.Sink.Category == sinkCat {
			return true
		}
	}
	return false
}
