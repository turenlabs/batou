package tsflow

import (
	"testing"

	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Rust AWS DynamoDB + Kinesis second-order read source tests.
// Values stored in DynamoDB / pushed to a Kinesis stream by an earlier
// (potentially attacker-controlled) request are read back here and flow
// into a dangerous sink — classic second-order taint.
// =========================================================================

func TestRust_AWS_DynamoDBGetItem_CommandInjection(t *testing.T) {
	code := `
use aws_sdk_dynamodb::Client;
use std::process::Command;

async fn handler(ddb: &Client) {
    let output = ddb.get_item().table_name("jobs").send().await.unwrap();
    Command::new(&output).output().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for DynamoDB get_item -> Command::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_AWS_DynamoDBBatchGetItem_CommandInjection(t *testing.T) {
	code := `
use aws_sdk_dynamodb::Client;
use std::process::Command;

async fn handler(ddb: &Client) {
    let output = ddb.batch_get_item().send().await.unwrap();
    Command::new(&output).output().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for DynamoDB batch_get_item -> Command::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_AWS_DynamoDBTransactGetItems_CommandInjection(t *testing.T) {
	code := `
use aws_sdk_dynamodb::Client;
use std::process::Command;

async fn handler(ddb: &Client) {
    let output = ddb.transact_get_items().send().await.unwrap();
    Command::new(&output).output().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for DynamoDB transact_get_items -> Command::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_AWS_KinesisGetRecords_CommandInjection(t *testing.T) {
	code := `
use aws_sdk_kinesis::Client;
use std::process::Command;

async fn handler(kinesis: &Client) {
    let output = kinesis.get_records().send().await.unwrap();
    Command::new(&output).output().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for Kinesis get_records -> Command::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative control: a constant string read from DynamoDB-style code with no
// tainted source must NOT produce a flow.
func TestRust_AWS_DynamoDB_Safe_ConstantCommand(t *testing.T) {
	code := `
use std::process::Command;

async fn handler() {
    let cmd = "ls -la";
    Command::new(cmd).output().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("did not expect a command injection flow for a constant command")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
