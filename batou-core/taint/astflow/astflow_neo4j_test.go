package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
)

// =========================================================================
// Neo4j Cypher Injection via neo4j-go-driver (CWE-943) tests
// =========================================================================

func TestAnalyzeGo_Neo4jSessionRun_CypherInjection(t *testing.T) {
	code := `package main

import (
	"context"
	"net/http"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func handler(ctx context.Context, session neo4j.SessionWithContext, r *http.Request) {
	name := r.URL.Query().Get("name")
	cypher := "MATCH (u:User {name: '" + name + "'}) RETURN u"
	session.Run(ctx, cypher, nil)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	found := false
	for _, f := range flows {
		if f.Sink.ID == "go.neo4j.session.run" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected Cypher injection flow for query param -> neo4j SessionWithContext.Run")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestAnalyzeGo_Neo4jManagedTransactionRun_CypherInjection(t *testing.T) {
	code := `package main

import (
	"context"
	"net/http"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func handler(ctx context.Context, tx neo4j.ManagedTransaction, r *http.Request) {
	label := r.URL.Query().Get("label")
	cypher := "MATCH (n:" + label + ") RETURN n"
	tx.Run(ctx, cypher, nil)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	found := false
	for _, f := range flows {
		if f.Sink.ID == "go.neo4j.managedtransaction.run" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected Cypher injection flow for query param -> neo4j ManagedTransaction.Run")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestAnalyzeGo_Neo4jExplicitTransactionRun_CypherInjection(t *testing.T) {
	code := `package main

import (
	"context"
	"net/http"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func handler(ctx context.Context, tx neo4j.ExplicitTransaction, r *http.Request) {
	id := r.URL.Query().Get("id")
	cypher := "MATCH (u:User {id: " + id + "}) DETACH DELETE u"
	tx.Run(ctx, cypher, nil)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	found := false
	for _, f := range flows {
		if f.Sink.ID == "go.neo4j.explicittransaction.run" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected Cypher injection flow for query param -> neo4j ExplicitTransaction.Run")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestAnalyzeGo_Neo4jExecuteQuery_CypherInjection(t *testing.T) {
	code := `package main

import (
	"context"
	"net/http"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func handler(ctx context.Context, driver neo4j.DriverWithContext, r *http.Request) {
	name := r.URL.Query().Get("name")
	cypher := "MERGE (u:User {name: '" + name + "'}) RETURN u"
	neo4j.ExecuteQuery(ctx, driver, cypher, nil, neo4j.EagerResultTransformer)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	found := false
	for _, f := range flows {
		if f.Sink.ID == "go.neo4j.executequery" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected Cypher injection flow for query param -> neo4j.ExecuteQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestAnalyzeGo_Neo4jV4TransactionRun_CypherInjection(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
)

func handler(tx neo4j.Transaction, r *http.Request) {
	id := r.URL.Query().Get("id")
	cypher := "MATCH (u:User {id: " + id + "}) SET u.admin = true"
	tx.Run(cypher, nil)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	found := false
	for _, f := range flows {
		if f.Sink.ID == "go.neo4j.v4.transaction.run" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected Cypher injection flow for query param -> neo4j v4 Transaction.Run")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestAnalyzeGo_Neo4jExecuteQuery_Safe_Parameterized(t *testing.T) {
	code := `package main

import (
	"context"
	"net/http"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func handler(ctx context.Context, driver neo4j.DriverWithContext, r *http.Request) {
	name := r.URL.Query().Get("name")
	neo4j.ExecuteQuery(ctx, driver,
		"MATCH (u:User {name: $name}) RETURN u",
		map[string]any{"name": name},
		neo4j.EagerResultTransformer)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Sink.ID == "go.neo4j.executequery" {
			t.Errorf("expected no Cypher injection for parameterized query, got src=%s", f.Source.ID)
		}
	}
}

func TestAnalyzeGo_Neo4jSessionRun_Safe_Hardcoded(t *testing.T) {
	code := `package main

import (
	"context"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func handler(ctx context.Context, session neo4j.SessionWithContext) {
	session.Run(ctx, "MATCH (u:User) RETURN count(u)", nil)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.ID == "go.neo4j.session.run" {
			t.Errorf("expected no Cypher injection for hardcoded statement, got src=%s", f.Source.ID)
		}
	}
}
