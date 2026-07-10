package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Swift — gRPC Swift v2 server-handler request sources
// =========================================================================
//
// gRPC Swift 2 (grpc/grpc-swift-2) is a first-class Swift server framework.
// A service handler conforming to ServiceProtocol / StreamingServiceProtocol
// receives a ServerRequest<Input> (or StreamingServerRequest<Input>) and
// reads the client-supplied, SwiftProtobuf-decoded payload via
// `request.message` (unary), `request.messages` (the inbound async stream),
// or the client-set headers via `request.metadata`. All three are
// attacker-controlled. These tests plumb each source into SQLite.swift's
// Connection.execute (swift.sqliteswift.execute, DangerousArgs [0],
// ObjectType "Connection" matched against receiver "db") and assert that the
// new sources fire. SQL/handler keywords ("Query(", "Path(", bare
// "GET"/"POST"/"DELETE", etc.) are kept out of the function bodies so the
// isWebHandlerFunc auto-taint path in walker.go doesn't seed parameters and
// mask whether the new source actually fires.

// --- ServerRequest.message (unary) -------------------------------------

func TestSwift_GRPC_RequestMessage_Injection(t *testing.T) {
	code := `
import GRPCCore
import SQLite

func lookup(request: ServerRequest<UserLookup>, db: Connection) async throws {
    let msg = request.message
    let actor = "\(msg)"
    let sql = "SELECT * FROM audit WHERE actor = '\(actor)'"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/Lookup.swift", rules.LangSwift)
	if !hasFlowFromSource(flows, "swift.grpc.request.message", taint.SnkSQLQuery) {
		t.Error("expected SQLi flow for request.message -> db.execute")
		for _, f := range flows {
			t.Logf("  flow: %s(%s) -> %s(%s)", f.Source.Category, f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

// Field access on the decoded message must still propagate taint: a handler
// almost always reads `request.message.<field>` rather than the whole proto.

func TestSwift_GRPC_RequestMessageField_Injection(t *testing.T) {
	code := `
import GRPCCore
import SQLite

func lookupField(request: ServerRequest<UserLookup>, db: Connection) async throws {
    let username = request.message.username
    let sql = "SELECT * FROM users WHERE name = '\(username)'"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/LookupField.swift", rules.LangSwift)
	if !hasFlowFromSource(flows, "swift.grpc.request.message", taint.SnkSQLQuery) {
		t.Error("expected SQLi flow for request.message.username -> db.execute")
		for _, f := range flows {
			t.Logf("  flow: %s(%s) -> %s(%s)", f.Source.Category, f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

// Abbreviated receiver `req` must match "ServerRequest" via the request
// heuristic in matcher.go.

func TestSwift_GRPC_ReqMessage_Injection(t *testing.T) {
	code := `
import GRPCCore
import SQLite

func handle(req: ServerRequest<Note>, db: Connection) async throws {
    let body = req.message
    let note = "\(body)"
    let sql = "SELECT * FROM notes WHERE body = '\(note)'"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/Handle.swift", rules.LangSwift)
	if !hasFlowFromSource(flows, "swift.grpc.request.message", taint.SnkSQLQuery) {
		t.Error("expected SQLi flow for req.message -> db.execute")
		for _, f := range flows {
			t.Logf("  flow: %s(%s) -> %s(%s)", f.Source.Category, f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- StreamingServerRequest.messages (client-streaming) ----------------

func TestSwift_GRPC_RequestMessages_Injection(t *testing.T) {
	code := `
import GRPCCore
import SQLite

func ingest(request: StreamingServerRequest<Event>, db: Connection) async throws {
    let stream = request.messages
    let payload = "\(stream)"
    let sql = "SELECT * FROM events WHERE tag = '\(payload)'"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/Ingest.swift", rules.LangSwift)
	if !hasFlowFromSource(flows, "swift.grpc.request.messages", taint.SnkSQLQuery) {
		t.Error("expected SQLi flow for request.messages -> db.execute")
		for _, f := range flows {
			t.Logf("  flow: %s(%s) -> %s(%s)", f.Source.Category, f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- ServerRequest.metadata (client headers) ---------------------------

func TestSwift_GRPC_RequestMetadata_Injection(t *testing.T) {
	code := `
import GRPCCore
import SQLite

func authish(request: ServerRequest<Ping>, db: Connection) async throws {
    let md = request.metadata
    let tenant = "\(md)"
    let sql = "SELECT * FROM tenants WHERE id = '\(tenant)'"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/Authish.swift", rules.LangSwift)
	if !hasFlowFromSource(flows, "swift.grpc.request.metadata", taint.SnkSQLQuery) {
		t.Error("expected SQLi flow for request.metadata -> db.execute")
		for _, f := range flows {
			t.Logf("  flow: %s(%s) -> %s(%s)", f.Source.Category, f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Negative: discarded reads + constant SQL → no flow ----------------

func TestSwift_GRPC_NoFlow_OnConstantSQL(t *testing.T) {
	code := `
import GRPCCore
import SQLite

func warm(request: ServerRequest<Ping>, stream: StreamingServerRequest<Ping>, db: Connection) async throws {
    _ = request.message
    _ = request.metadata
    _ = stream.messages
    let sql = "SELECT 1"
    try db.execute(sql)
}
`
	flows := Analyze(code, "/app/Warm.swift", rules.LangSwift)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did NOT expect SnkSQLQuery flow for discarded gRPC reads + constant SQL")
		for _, f := range flows {
			t.Logf("  flow: %s(%s) -> %s(%s)", f.Source.Category, f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Registration sanity: new source IDs are present in the catalog ----

func TestSwift_GRPCSources_Registered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangSwift)
	want := map[string]bool{
		"swift.grpc.request.message":  false,
		"swift.grpc.request.messages": false,
		"swift.grpc.request.metadata": false,
	}
	for _, s := range cat.Sources() {
		if _, ok := want[s.ID]; ok {
			want[s.ID] = true
			if s.Category != taint.SrcUserInput {
				t.Errorf("source %s: expected Category SrcUserInput, got %v", s.ID, s.Category)
			}
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("expected source %s to be registered in the Swift catalog", id)
		}
	}
}
