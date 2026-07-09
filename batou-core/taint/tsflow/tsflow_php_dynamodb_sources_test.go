package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// PHP — AWS DynamoDB (aws-sdk-php DynamoDbClient) second-order read sources.
//
// PHP already modeled DynamoDB *writes* (php.aws.dynamodb.executestatement,
// a PartiQL injection sink) and AWS S3 GetObject / SQS ReceiveMessage as
// external second-order sources, but the DynamoDbClient *read* operations
// (getItem / query / scan / batchGetItem / transactGetItems) were missing.
// A value an untrusted user stored via putItem on one request and read back
// later therefore did not carry taint into a downstream command / SQL /
// deserialization sink.
//
// Mirrors the cross-language DynamoDB second-order read-source wave
// (Perl Paws::DynamoDB, Ruby aws-sdk-dynamodb, Go aws-sdk-go-v2, Python boto3).
//
// Receiver "$dynamoDb" matches the catalog ObjectType "DynamoDbClient"
// (the same short class name the existing executeStatement sink uses) via the
// tsflow prefix-abbreviation heuristic ("dynamodb" is a prefix of
// "dynamodbclient"). Kept in a dedicated file to avoid the tsflow_test.go
// merge bottleneck.
// =========================================================================

func TestPHP_DynamoDB_GetItem_SecondOrder_Deserialize(t *testing.T) {
	code := `<?php
function load_user() {
    $res = $dynamoDb->getItem(['TableName' => 'Users', 'Key' => $key]);
    $obj = unserialize($res);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected SnkDeserialize flow for $dynamoDb->getItem() -> unserialize()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPHP_DynamoDB_Query_SecondOrder_Command(t *testing.T) {
	code := `<?php
function run_jobs() {
    $res = $dynamoDb->query(['TableName' => 'Jobs']);
    exec($res[0]);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $dynamoDb->query() -> exec()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPHP_DynamoDB_Scan_SecondOrder_Command(t *testing.T) {
	code := `<?php
function scan_all() {
    $res = $dynamoDb->scan(['TableName' => 'Tasks']);
    system($res);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $dynamoDb->scan() -> system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPHP_DynamoDB_BatchGetItem_SecondOrder_Deserialize(t *testing.T) {
	code := `<?php
function batch_load() {
    $res = $dynamoDb->batchGetItem(['RequestItems' => $items]);
    $obj = unserialize($res);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected SnkDeserialize flow for $dynamoDb->batchGetItem() -> unserialize()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPHP_DynamoDB_TransactGetItems_SecondOrder_Command(t *testing.T) {
	code := `<?php
function transact_load() {
    $res = $dynamoDb->transactGetItems(['TransactItems' => $items]);
    exec($res);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for $dynamoDb->transactGetItems() -> exec()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative control: a hardcoded literal flowing to the same sink must NOT
// produce a taint flow — proving the DynamoDB read is what introduces taint,
// not the sink alone.
func TestPHP_DynamoDB_Constant_NoFlow(t *testing.T) {
	code := `<?php
function safe() {
    $res = "static-job-id";
    exec($res);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("did not expect SnkCommand flow for a hardcoded literal -> exec()")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
