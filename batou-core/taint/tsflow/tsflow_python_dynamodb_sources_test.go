package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Python boto3 DynamoDB read sources — second-order (stored) injection.
//
// DynamoDB holds attacker-controllable data written on an earlier request.
// Reading those items back (get_item/query/scan/PartiQL/transactions) and
// flowing them into a SQL/command/eval sink is a stored injection. The
// high-level resource API binds the receiver to `table`; the low-level
// client API binds it to `client`. Module-level statements are not walked
// by the Python tsflow walker, so every fixture wraps the call site in a
// `def handler():` block.
// =========================================================================

func TestPython_DynamoDB_SourcesRegistered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangPython)
	if cat == nil {
		t.Fatal("Python catalog not loaded")
	}
	found := map[string]bool{}
	for _, s := range cat.Sources() {
		found[s.ID] = true
	}
	want := []string{
		"py.boto3.dynamodb.table.get_item",
		"py.boto3.dynamodb.table.query",
		"py.boto3.dynamodb.table.scan",
		"py.boto3.dynamodb.client.get_item",
		"py.boto3.dynamodb.client.batch_get_item",
		"py.boto3.dynamodb.client.execute_statement",
		"py.boto3.dynamodb.client.batch_execute_statement",
		"py.boto3.dynamodb.client.transact_get_items",
	}
	for _, id := range want {
		if !found[id] {
			t.Errorf("missing expected DynamoDB source: %s", id)
		}
	}
}

// --- High-level resource (Table) interface ---

func TestPython_DynamoDBTableGetItem_SQLi(t *testing.T) {
	code := `
def handler():
    resp = table.get_item(Key={"id": "1"})
    item = resp["Item"]
    cursor.execute("SELECT * FROM logs WHERE name = '" + item["name"] + "'")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection from table.get_item() -> cursor.execute()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_DynamoDBTableQuery_CommandInjection(t *testing.T) {
	code := `
import os

def handler():
    resp = table.query(KeyConditionExpression="pk = :p")
    for item in resp["Items"]:
        os.system(item["cmd"])
`
	flows := Analyze(code, "/app/worker.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection from table.query() -> os.system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_DynamoDBTableScan_Eval(t *testing.T) {
	code := `
def handler():
    resp = table.scan()
    for item in resp["Items"]:
        eval(item["expr"])
`
	flows := Analyze(code, "/app/eval.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval injection from table.scan() -> eval()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Low-level client interface ---

func TestPython_DynamoDBClientGetItem_SQLi(t *testing.T) {
	code := `
def handler():
    resp = client.get_item(TableName="Users", Key={"id": {"S": "1"}})
    item = resp["Item"]
    cursor.execute("SELECT * FROM t WHERE name = '" + item["name"]["S"] + "'")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection from client.get_item() -> cursor.execute()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_DynamoDBClientBatchGetItem_CommandInjection(t *testing.T) {
	code := `
import os

def handler():
    resp = client.batch_get_item(RequestItems={"Users": {"Keys": []}})
    responses = resp["Responses"]
    for item in responses["Users"]:
        os.system(item["cmd"])
`
	flows := Analyze(code, "/app/batch.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection from client.batch_get_item() -> os.system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_DynamoDBClientExecuteStatement_SQLi(t *testing.T) {
	code := `
def handler():
    resp = client.execute_statement(Statement="SELECT * FROM Users")
    for item in resp["Items"]:
        cursor.execute("INSERT INTO audit VALUES ('" + item["name"]["S"] + "')")
`
	flows := Analyze(code, "/app/partiql.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection from client.execute_statement() -> cursor.execute()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_DynamoDBClientTransactGetItems_CommandInjection(t *testing.T) {
	code := `
import os

def handler():
    resp = client.transact_get_items(TransactItems=[])
    for item in resp["Responses"]:
        os.system(item["Item"]["cmd"]["S"])
`
	flows := Analyze(code, "/app/txn.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection from client.transact_get_items() -> os.system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Negative control: constant DynamoDB read with no tainted flow ---

func TestPython_DynamoDBConstantRead_NoFlow(t *testing.T) {
	code := `
def handler():
    resp = table.get_item(Key={"id": "1"})
    cursor.execute("SELECT * FROM logs WHERE id = 1")
`
	flows := Analyze(code, "/app/safe.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did not expect a SQL flow: the query is a constant, DynamoDB result is unused")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
