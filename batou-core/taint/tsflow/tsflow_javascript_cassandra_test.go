package tsflow

import (
	"testing"

	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// JavaScript/TypeScript — DataStax cassandra-driver Node.js + ScyllaDB +
// DSE — CQL injection (CWE-943).
//
// Covers cassandra-driver entries added to javascript_sinks.go:
//   - js.cassandra.client.eachrow
//   - js.cassandra.client.executeasync
//   - js.cassandra.client.batch
//   - js.cassandra.simplestatement
//
// @scylladb/scylla-driver and dse-driver are API-compatible forks of
// DataStax cassandra-driver; the same sink methods cover all three.
// Each test wires an Express-style request source through string
// concatenation/template literals into the sink and asserts the
// js.cassandra.* sink fires.
// =========================================================================

func TestJS_Cassandra_Client_EachRow_CQLInjection(t *testing.T) {
	code := `
const cassandra = require('cassandra-driver');
const client = new cassandra.Client({ contactPoints: ['127.0.0.1'], localDataCenter: 'dc1' });

function searchEach(req, res) {
    const userId = req.query.userId;
    const cql = "SELECT * FROM users WHERE id = '" + userId + "'";
    client.eachRow(cql, [], (n, row) => {
        res.write(JSON.stringify(row));
    });
}
`
	flows := Analyze(code, "/app/handlers/each.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.cassandra.client.eachrow") {
		t.Error("expected js.cassandra.client.eachrow flow from req.query -> client.eachRow()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJS_Cassandra_Client_ExecuteAsync_CQLInjection(t *testing.T) {
	code := `
const cassandra = require('cassandra-driver');
const client = new cassandra.Client({ contactPoints: ['127.0.0.1'], localDataCenter: 'dc1' });

async function lookup(req, res) {
    const name = req.body.name;
    await client.executeAsync(` + "`" + `SELECT * FROM users WHERE name = '${name}'` + "`" + `);
}
`
	flows := Analyze(code, "/app/handlers/lookup.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.cassandra.client.executeasync") {
		t.Error("expected js.cassandra.client.executeasync flow from req.body -> client.executeAsync()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJS_Cassandra_Client_Batch_CQLInjection(t *testing.T) {
	code := `
const cassandra = require('cassandra-driver');
const client = new cassandra.Client({ contactPoints: ['127.0.0.1'], localDataCenter: 'dc1' });

async function logBatch(req, res) {
    const msg = req.body.msg;
    const queries = [
        "INSERT INTO logs (msg) VALUES ('" + msg + "')",
        "UPDATE counters SET n = n + 1 WHERE k = 'logs'"
    ];
    await client.batch(queries, { prepare: false });
}
`
	flows := Analyze(code, "/app/handlers/batch.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.cassandra.client.batch") {
		t.Error("expected js.cassandra.client.batch flow from req.body -> client.batch()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJS_Cassandra_SimpleStatement_CQLInjection(t *testing.T) {
	code := `
const cassandra = require('cassandra-driver');
const client = new cassandra.Client({ contactPoints: ['127.0.0.1'], localDataCenter: 'dc1' });

async function buildStmt(req, res) {
    const table = req.query.table;
    const cql = "SELECT * FROM " + table + " WHERE id = ?";
    const stmt = new cassandra.types.SimpleStatement(cql);
    await client.execute(stmt, [1]);
}
`
	flows := Analyze(code, "/app/handlers/simplestmt.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.cassandra.simplestatement") {
		t.Error("expected js.cassandra.simplestatement flow from req.query -> SimpleStatement(cql)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJS_Cassandra_Scylla_EachRow_CQLInjection(t *testing.T) {
	// @scylladb/scylla-driver is an API-compatible fork of cassandra-driver.
	// The same sink method names cover both drivers.
	code := `
const cassandra = require('@scylladb/scylla-driver');
const client = new cassandra.Client({ contactPoints: ['127.0.0.1'], localDataCenter: 'dc1' });

function scan(req, res) {
    const tag = req.query.tag;
    const cql = ` + "`" + `SELECT * FROM events WHERE tag = '${tag}'` + "`" + `;
    client.eachRow(cql, [], (n, row) => {
        res.write(JSON.stringify(row));
    });
}
`
	flows := Analyze(code, "/app/handlers/scylla.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.cassandra.client.eachrow") {
		t.Error("expected js.cassandra.client.eachrow flow from req.query -> Scylla client.eachRow()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}
