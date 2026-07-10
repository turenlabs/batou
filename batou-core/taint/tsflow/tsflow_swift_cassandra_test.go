package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Swift — Apple swift-cassandra-client CQL injection tests (CWE-943)
// =========================================================================
//
// Apple's swift-cassandra-client (https://github.com/apple/swift-cassandra-client)
// exposes three CQL-string entry points where a raw CQL argument enables
// CQL injection when tainted:
//
//   1. cassandraClient.query(_:) / cassandraClient.run(_:) — top-level
//      shortcut methods on the lazy default session.
//   2. session.query(_:) / session.run(_:) — same shape on a CassandraSession
//      returned by makeSession(keyspace:) or withSession(keyspace:).
//   3. Statement(query:parameters:options:) — explicit Statement init that
//      bakes the CQL string into a reusable statement.
//
// The safe pattern is `?` placeholders bound via `parameters: [.string(…)]`.

// CassandraClient.query(_:) with tainted CQL string interpolation.
func TestSwift_Cassandra_CassandraClient_Query_Tainted(t *testing.T) {
	code := `
import CassandraClient

func handler(input: String) async throws {
    let rows = try await cassandraClient.query("SELECT * FROM users WHERE id = '\(input)'")
    _ = rows
}
`
	flows := Analyze(code, "/app/UsersHandler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected CQL injection flow for req.parameters -> cassandraClient.query()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// CassandraClient.run(_:) — DDL/INSERT path with tainted interpolation.
func TestSwift_Cassandra_CassandraClient_Run_Tainted(t *testing.T) {
	code := `
import CassandraClient

func handler(input: String) async throws {
    try await cassandraClient.run("INSERT INTO logs (msg) VALUES ('\(input)')")
}
`
	flows := Analyze(code, "/app/LogsHandler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected CQL injection flow for input -> cassandraClient.run()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// CassandraSession.query(_:) — per-keyspace session from makeSession.
func TestSwift_Cassandra_Session_Query_Tainted(t *testing.T) {
	code := `
import CassandraClient

func handler(input: String) async throws {
    let session = try await cassandraClient.makeSession(keyspace: "app")
    let rows = try await session.query("SELECT * FROM users WHERE name = '\(input)'")
    _ = rows
}
`
	flows := Analyze(code, "/app/UsersHandler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected CQL injection flow for req.parameters -> session.query()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// CassandraSession.run(_:) — per-keyspace session DDL/INSERT path.
func TestSwift_Cassandra_Session_Run_Tainted(t *testing.T) {
	code := `
import CassandraClient

func handler(input: String) async throws {
    let session = try await cassandraClient.makeSession(keyspace: "audit")
    try await session.run("INSERT INTO events (data) VALUES ('\(input)')")
}
`
	flows := Analyze(code, "/app/EventsHandler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected CQL injection flow for input -> session.run()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Statement(query:) constructor — the explicit prepared-statement path.
// Even though execute(statement:) takes the Statement object, the injection
// happens at Statement construction when the CQL string is concatenated.
func TestSwift_Cassandra_Statement_Init_Tainted(t *testing.T) {
	code := `
import CassandraClient

func handler(input: String) async throws {
    let stmt = try Statement(query: "INSERT INTO t (name) VALUES ('\(input)')", parameters: [])
    try await cassandraClient.execute(statement: stmt)
}
`
	flows := Analyze(code, "/app/MigrateHandler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected CQL injection flow for input -> Statement(query:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Safe: tainted value passed via `parameters:` binding, not interpolated into
// the CQL string. Should not produce a swift.cassandra.* flow.
func TestSwift_Cassandra_ParameterizedBinding_Safe(t *testing.T) {
	code := `
import CassandraClient
import Vapor

func handler(req: Request) async throws {
    let name = req.query["name"] ?? ""
    let stmt = try Statement(
        query: "SELECT * FROM users WHERE name = ?",
        parameters: [.string(name)]
    )
    _ = try await cassandraClient.execute(statement: stmt)
}
`
	flows := Analyze(code, "/app/SafeHandler.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery &&
			(f.Sink.ID == "swift.cassandra.statement.init" ||
				f.Sink.ID == "swift.cassandra.cassandraclient.query" ||
				f.Sink.ID == "swift.cassandra.cassandraclient.run" ||
				f.Sink.ID == "swift.cassandra.session.query" ||
				f.Sink.ID == "swift.cassandra.session.run") {
			t.Errorf("expected NO swift.cassandra.* flow when tainted value only reaches `parameters:` binding, got sink %s", f.Sink.ID)
		}
	}
}
