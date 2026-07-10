package astflow

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// Catalog registration: each new AWS DynamoDB read source is indexed under
// its method name with category SrcDatabase.
func TestCatalogMatcher_DynamoDBReadSourcesRegistered(t *testing.T) {
	cat := taint.GetCatalog("go")
	if cat == nil {
		t.Fatal("Go catalog not registered")
	}

	matcher := NewCatalogMatcher(cat.Sources(), nil, nil, nil)

	methods := []string{
		"GetItem", "BatchGetItem", "Query", "Scan", "TransactGetItems",
		"GetItemWithContext", "QueryWithContext", "ScanWithContext",
		"BatchGetItemWithContext",
	}
	for _, method := range methods {
		found := false
		for _, src := range matcher.sourcesByMethod[method] {
			if src.Category == taint.SrcDatabase && strings.HasPrefix(src.ID, "go.dynamodb.") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %q to be indexed as a DynamoDB read source (SrcDatabase)", method)
		}
	}
}

// End-to-end second-order flow tests: DynamoDB read → dangerous sink.
// These mirror the existing TestAnalyzeGo_RedisGet_SecondOrderSQLi /
// TestAnalyzeGo_MongoFindOne_SecondOrderSQLi fixture style — the source
// call's return value is treated as the persisted item carried downstream.

func TestAnalyzeGo_DynamoDBGetItem_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

func handler(svc *dynamodb.Client, db *sql.DB) {
	out := svc.GetItem(nil, nil)
	db.Query("SELECT * FROM logs WHERE actor = '" + out + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: DynamoDB GetItem → db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
	if !hasSourceCategory(flows, taint.SrcDatabase) {
		t.Error("expected source category SrcDatabase")
	}
}

func TestAnalyzeGo_DynamoDBBatchGetItem_SecondOrderCommand(t *testing.T) {
	code := `package main

import (
	"os/exec"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

func handler(svc *dynamodb.Client) {
	out := svc.BatchGetItem(nil, nil)
	exec.Command("sh", "-c", "echo "+out)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected second-order command injection: DynamoDB BatchGetItem → exec.Command")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_DynamoDBQuery_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

func handler(svc *dynamodb.Client, db *sql.DB) {
	out := svc.Query(nil, nil)
	db.Query("SELECT * FROM logs WHERE actor = '" + out + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: DynamoDB Query → db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_DynamoDBScan_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

func handler(svc *dynamodb.Client, db *sql.DB) {
	out := svc.Scan(nil, nil)
	db.Query("SELECT * FROM logs WHERE actor = '" + out + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: DynamoDB Scan → db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_DynamoDBTransactGetItems_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

func handler(svc *dynamodb.Client, db *sql.DB) {
	out := svc.TransactGetItems(nil, nil)
	db.Query("SELECT * FROM logs WHERE actor = '" + out + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: DynamoDB TransactGetItems → db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// aws-sdk-go v1 *WithContext variants. v1 client values usually come from
// dynamodb.New(sess) with no statically-known type, so the receiver name
// heuristic (svc → *dynamodb.Client/*dynamodb.DynamoDB) does the matching.
func TestAnalyzeGo_DynamoDBWithContextVariants_SecondOrderSQLi(t *testing.T) {
	for _, method := range []string{
		"GetItemWithContext", "QueryWithContext", "ScanWithContext", "BatchGetItemWithContext",
	} {
		code := `package main

import "database/sql"

func handler(db *sql.DB) {
	svc := newDynamoClient()
	out := svc.` + method + `(nil, nil)
	db.Query("SELECT * FROM logs WHERE actor = '" + out + "'")
}
`
		flows := AnalyzeGo(code, "/app/handler.go")
		if !hasTaintFlow(flows, taint.SnkSQLQuery) {
			t.Errorf("expected second-order SQL injection: DynamoDB %s → db.Query", method)
			for _, f := range flows {
				t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
			}
		}
	}
}

// Receiver-name heuristic path: when the receiver's type is not statically
// known, astflow's matchesReceiverType maps "ddb" to *dynamodb.Client.
func TestAnalyzeGo_DynamoDBGetItem_ReceiverHeuristic(t *testing.T) {
	code := `package main

import "database/sql"

func handler(db *sql.DB) {
	out := ddb.GetItem(nil, nil)
	db.Query("SELECT * FROM logs WHERE actor = '" + out + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection via receiver heuristic: ddb.GetItem → db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Negative control: a discarded DynamoDB read plus a literal query value
// must not produce a SrcDatabase flow.
func TestAnalyzeGo_DynamoDBReadSource_SafeLiteral(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

func handler(svc *dynamodb.Client, db *sql.DB) {
	actor := "hardcoded_actor"
	_ = svc.GetItem(nil, nil)
	db.Query("SELECT * FROM logs WHERE actor = '" + actor + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Source.Category == taint.SrcDatabase {
			t.Error("should not detect a DynamoDB source flow when the query value is a literal")
		}
	}
}
