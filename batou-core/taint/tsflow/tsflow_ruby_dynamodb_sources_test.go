package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"

	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Ruby — AWS DynamoDB read sources (aws-sdk-dynamodb), second-order/stored
// taint: data written to DynamoDB by one request and read back by a later
// one. Mirrors the cross-language wave (python boto3 #956, perl Paws #970,
// java DynamoDB). Low-level Aws::DynamoDB::Client is idiomatically bound to
// `client`; the high-level Aws::DynamoDB::Resource table handle to `table`.
//
// Test note (mirrors tsflow_ruby_db_read_sources_test.go): each fixture
// assigns the source call to its own variable first, then extracts a field
// with chained access (`resp.item["col"]`). Functions take no params so
// seedParams() can't auto-taint anything — the DynamoDB read is the only
// taint origin.
// =========================================================================

func TestRuby_DynamoDB_ClientGetItem_CommandInjection(t *testing.T) {
	code := `
require "aws-sdk-dynamodb"

def show_profile
  client = Aws::DynamoDB::Client.new
  resp = client.get_item(table_name: "users", key: { "id" => "1" })
  name = resp.item["name"]
  system("echo " + name)
end
`
	flows := Analyze(code, "/app/services/profile.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from DynamoDB Client#get_item result -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_DynamoDB_ClientBatchGetItem_SQLInjection(t *testing.T) {
	code := `
require "aws-sdk-dynamodb"

def report
  client = Aws::DynamoDB::Client.new
  resp = client.batch_get_item(request_items: {})
  note = resp.responses["audit"][0]["note"]
  db = Mysql2::Client.new(host: "localhost", database: "app")
  db.query("SELECT * FROM logs WHERE note = '" + note + "'")
end
`
	flows := Analyze(code, "/app/jobs/report.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from DynamoDB Client#batch_get_item result -> Mysql2 query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_DynamoDB_ClientTransactGetItems_CommandInjection(t *testing.T) {
	code := `
require "aws-sdk-dynamodb"

def run
  client = Aws::DynamoDB::Client.new
  resp = client.transact_get_items(transact_items: [])
  cmd = resp.responses[0]["cmd"]
  system(cmd)
end
`
	flows := Analyze(code, "/app/workers/run.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from DynamoDB Client#transact_get_items result -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_DynamoDB_ClientExecuteStatement_CommandInjection(t *testing.T) {
	code := `
require "aws-sdk-dynamodb"

def lookup
  client = Aws::DynamoDB::Client.new
  resp = client.execute_statement(statement: "SELECT * FROM users")
  host = resp.items[0]["host"]
  system("ping " + host)
end
`
	flows := Analyze(code, "/app/services/lookup.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from DynamoDB Client#execute_statement result -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_DynamoDB_ClientBatchExecuteStatement_CommandInjection(t *testing.T) {
	code := `
require "aws-sdk-dynamodb"

def lookup
  client = Aws::DynamoDB::Client.new
  resp = client.batch_execute_statement(statements: [])
  host = resp.responses[0]["host"]
  system("ping " + host)
end
`
	flows := Analyze(code, "/app/services/batch_lookup.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from DynamoDB Client#batch_execute_statement result -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_DynamoDB_TableGetItem_CommandInjection(t *testing.T) {
	code := `
require "aws-sdk-dynamodb"

def show
  table = Aws::DynamoDB::Resource.new.table("users")
  resp = table.get_item(key: { "id" => "1" })
  name = resp.item["name"]
  system("echo " + name)
end
`
	flows := Analyze(code, "/app/services/show.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from DynamoDB Table#get_item result -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_DynamoDB_TableQuery_CommandInjection(t *testing.T) {
	code := `
require "aws-sdk-dynamodb"

def list
  table = Aws::DynamoDB::Resource.new.table("events")
  resp = table.query(key_condition_expression: "id = :id")
  cmd = resp.items[0]["cmd"]
  system(cmd)
end
`
	flows := Analyze(code, "/app/services/list.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from DynamoDB Table#query result -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_DynamoDB_TableScan_CommandInjection(t *testing.T) {
	code := `
require "aws-sdk-dynamodb"

def all
  table = Aws::DynamoDB::Resource.new.table("hosts")
  resp = table.scan(limit: 10)
  host = resp.items[0]["host"]
  system("ping " + host)
end
`
	flows := Analyze(code, "/app/services/all.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from DynamoDB Table#scan result -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// Negative control: a constant DynamoDB read (no user data flows in) with a
// constant command must NOT produce a flow — proves the entry isn't a blanket
// taint on every get_item/query/scan, and that the flow above comes from the
// source, not seedParams.
func TestRuby_DynamoDB_NegativeControl_NoFlow(t *testing.T) {
	code := `
require "aws-sdk-dynamodb"

def healthcheck
  client = Aws::DynamoDB::Client.new
  resp = client.get_item(table_name: "users", key: { "id" => "1" })
  system("echo ok")
end
`
	flows := Analyze(code, "/app/services/health.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("did not expect a command injection flow when the DynamoDB result is unused (constant command)")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}
