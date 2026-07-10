package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// C++ AWS SDK for C++ second-order read sources
//
// The official AWS SDK for C++ returns an Outcome from each read operation;
// the wrapped result holds data previously stored in the service (S3 object
// bodies, DynamoDB items, SQS message bodies, Kinesis records). If an earlier
// write path stored attacker-controlled data without validation, that data
// re-enters the program tainted on read — second-order injection.
//
// These pair with the existing cpp.aws.* injection SINKS in cpp_sinks.go
// (Athena / DynamoDB PartiQL / Redshift Data SQL setters).
//
// The read call taints the returned Outcome (Assigns "return"). Application
// code then pulls a field out of the result; the fixtures model that
// extraction as a helper that takes the tainted outcome as an argument, so
// the extracted value carries taint into the sink — the same arg→return
// propagation shape the mongocxx find_one tests rely on (a multi-level method
// chain *assigned directly* off a tainted receiver does NOT propagate in
// tsflow, so we reference the outcome as an argument instead). Fixtures are
// wrapped in plain no-parameter functions so the tsflow web-handler heuristic
// cannot introduce taint: the new source entry is the only taint origin.
//
// Receivers are named after the client type's final `::` segment
// (`s3Client`, `dynamoDbClient`, `sqsClient`, `kinesisClient`) so the tsflow
// matcher scopes by ObjectType.
// =========================================================================

func TestCPP_AWS_S3_GetObject_SecondOrderCommand(t *testing.T) {
	code := `
#include <aws/s3/S3Client.h>
#include <aws/s3/model/GetObjectRequest.h>
#include <string>
#include <cstdlib>

std::string readBody(const Aws::S3::Model::GetObjectOutcome &o);

void replay() {
    Aws::S3::S3Client s3Client;
    Aws::S3::Model::GetObjectRequest request;
    request.SetBucket("uploads");
    request.SetKey("script.txt");
    auto outcome = s3Client.GetObject(request);
    std::string body = readBody(outcome);
    system(body.c_str());
}
`
	flows := Analyze(code, "/app/aws_s3_getobject.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected second-order command flow: S3Client::GetObject result -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_AWS_DynamoDB_GetItem_SecondOrderSQLi(t *testing.T) {
	code := `
#include <aws/dynamodb/DynamoDBClient.h>
#include <aws/dynamodb/model/GetItemRequest.h>
#include <cppconn/statement.h>
#include <string>

std::string attrValue(const Aws::DynamoDB::Model::GetItemOutcome &o, const char *k);

void mirror() {
    Aws::DynamoDB::DynamoDBClient dynamoDbClient;
    Aws::DynamoDB::Model::GetItemRequest request;
    request.SetTableName("users");
    auto outcome = dynamoDbClient.GetItem(request);
    std::string name = attrValue(outcome, "name");
    sql::Statement *stmt = nullptr;
    std::string q = "INSERT INTO audit (who) VALUES ('" + name + "')";
    stmt->execute(q);
}
`
	flows := Analyze(code, "/app/aws_dynamo_getitem.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL flow: DynamoDBClient::GetItem result -> Statement::execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_AWS_DynamoDB_Query_SecondOrderSQLi(t *testing.T) {
	code := `
#include <aws/dynamodb/DynamoDBClient.h>
#include <aws/dynamodb/model/QueryRequest.h>
#include <cppconn/statement.h>
#include <string>

std::string firstRef(const Aws::DynamoDB::Model::QueryOutcome &o);

void copyRows() {
    Aws::DynamoDB::DynamoDBClient dynamoDbClient;
    Aws::DynamoDB::Model::QueryRequest request;
    request.SetTableName("orders");
    auto outcome = dynamoDbClient.Query(request);
    std::string ref = firstRef(outcome);
    sql::Statement *stmt = nullptr;
    std::string q = "UPDATE orders SET ref = '" + ref + "' WHERE id = 1";
    stmt->execute(q);
}
`
	flows := Analyze(code, "/app/aws_dynamo_query.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL flow: DynamoDBClient::Query result -> Statement::execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_AWS_DynamoDB_Scan_SecondOrderSQLi(t *testing.T) {
	code := `
#include <aws/dynamodb/DynamoDBClient.h>
#include <aws/dynamodb/model/ScanRequest.h>
#include <cppconn/statement.h>
#include <string>

std::string firstToken(const Aws::DynamoDB::Model::ScanOutcome &o);

void sweep() {
    Aws::DynamoDB::DynamoDBClient dynamoDbClient;
    Aws::DynamoDB::Model::ScanRequest request;
    request.SetTableName("tokens");
    auto outcome = dynamoDbClient.Scan(request);
    std::string tok = firstToken(outcome);
    sql::Statement *stmt = nullptr;
    std::string q = "DELETE FROM tokens WHERE tok = '" + tok + "'";
    stmt->execute(q);
}
`
	flows := Analyze(code, "/app/aws_dynamo_scan.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL flow: DynamoDBClient::Scan result -> Statement::execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_AWS_DynamoDB_BatchGetItem_SecondOrderCommand(t *testing.T) {
	code := `
#include <aws/dynamodb/DynamoDBClient.h>
#include <aws/dynamodb/model/BatchGetItemRequest.h>
#include <string>
#include <cstdlib>

std::string firstCommand(const Aws::DynamoDB::Model::BatchGetItemOutcome &o);

void batch() {
    Aws::DynamoDB::DynamoDBClient dynamoDbClient;
    Aws::DynamoDB::Model::BatchGetItemRequest request;
    auto outcome = dynamoDbClient.BatchGetItem(request);
    std::string cmd = firstCommand(outcome);
    system(cmd.c_str());
}
`
	flows := Analyze(code, "/app/aws_dynamo_batchget.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected second-order command flow: DynamoDBClient::BatchGetItem result -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_AWS_SQS_ReceiveMessage_SecondOrderCommand(t *testing.T) {
	code := `
#include <aws/sqs/SQSClient.h>
#include <aws/sqs/model/ReceiveMessageRequest.h>
#include <string>
#include <cstdlib>

std::string firstMessageBody(const Aws::SQS::Model::ReceiveMessageOutcome &o);

void drain() {
    Aws::SQS::SQSClient sqsClient;
    Aws::SQS::Model::ReceiveMessageRequest request;
    request.SetQueueUrl("https://sqs.us-east-1.amazonaws.com/123/work");
    auto outcome = sqsClient.ReceiveMessage(request);
    std::string body = firstMessageBody(outcome);
    system(body.c_str());
}
`
	flows := Analyze(code, "/app/aws_sqs_receive.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected second-order command flow: SQSClient::ReceiveMessage result -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_AWS_Kinesis_GetRecords_SecondOrderCommand(t *testing.T) {
	code := `
#include <aws/kinesis/KinesisClient.h>
#include <aws/kinesis/model/GetRecordsRequest.h>
#include <string>
#include <cstdlib>

std::string firstRecordData(const Aws::Kinesis::Model::GetRecordsOutcome &o);

void consume() {
    Aws::Kinesis::KinesisClient kinesisClient;
    Aws::Kinesis::Model::GetRecordsRequest request;
    request.SetShardIterator("AAAA");
    auto outcome = kinesisClient.GetRecords(request);
    std::string payload = firstRecordData(outcome);
    system(payload.c_str());
}
`
	flows := Analyze(code, "/app/aws_kinesis_getrecords.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected second-order command flow: KinesisClient::GetRecords result -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ── Negative regression — a constant value (no AWS read) yields no flow ───

func TestCPP_AWS_DynamoDB_ConstantValue_NoFlow(t *testing.T) {
	code := `
#include <cppconn/statement.h>
#include <string>

void seed() {
    std::string name = "system";
    sql::Statement *stmt = nullptr;
    std::string q = "INSERT INTO audit (who) VALUES ('" + name + "')";
    stmt->execute(q);
}
`
	flows := Analyze(code, "/app/aws_dynamo_const.cpp", rules.LangCPP)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did not expect a SQL flow when no AWS read feeds the query")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
