package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Tests for Neo4j Cypher-injection sinks in JavaScript/TypeScript (CWE-943).
// neo4j-driver is the official Node.js driver. Cypher queries built by
// concatenation or template literals from user input let attackers alter
// graph semantics (MATCH/CREATE/DELETE). Safe code passes user values via a
// parameters object using $name placeholders:
//   session.run('MATCH (u:User {name: $name}) RETURN u', { name: userInput })
//
// Mirror of the Java neo4j sinks (tsflow_java_neo4j_test.go).

// --- js.neo4j.session.run: positive flow from req.query to session.run(cypher) ---

func TestJS_Neo4j_Session_Run_CypherInjection(t *testing.T) {
	code := `
function getUser(req, res) {
    const name = req.query.name;
    const session = driver.session();
    const cypher = "MATCH (u:User {name: '" + name + "'}) RETURN u";
    session.run(cypher);
}
`
	flows := Analyze(code, "/app/routes/users.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.neo4j.session.run") {
		t.Error("expected js.neo4j.session.run flow from req.query -> session.run()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- js.neo4j.tx.run: positive flow using explicit beginTransaction ---

func TestJS_Neo4j_Tx_Run_CypherInjection(t *testing.T) {
	code := `
function createLabel(req, res) {
    const label = req.body.label;
    const session = driver.session();
    const tx = session.beginTransaction();
    const cypher = "CREATE (:" + label + " {id: 1})";
    tx.run(cypher);
    tx.commit();
}
`
	flows := Analyze(code, "/app/routes/labels.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.neo4j.tx.run") {
		t.Error("expected js.neo4j.tx.run flow from req.body -> tx.run()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- js.neo4j.driver.executequery: v5.5+ unified API ---

func TestJS_Neo4j_Driver_ExecuteQuery_CypherInjection(t *testing.T) {
	code := `
function lookup(req, res) {
    const id = req.query.id;
    const cypher = "MATCH (n) WHERE n.id = '" + id + "' RETURN n";
    driver.executeQuery(cypher);
}
`
	flows := Analyze(code, "/app/routes/lookup.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.neo4j.driver.executequery") {
		t.Error("expected js.neo4j.driver.executequery flow from req.query -> driver.executeQuery()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Safe: parameterized Cypher (literal query + params object) ---

func TestJS_Neo4j_Session_Run_Parameterized_NoFlow(t *testing.T) {
	code := `
function getUser(req, res) {
    const name = req.query.name;
    const session = driver.session();
    session.run("MATCH (u:User {name: $name}) RETURN u", { name: name });
}
`
	flows := Analyze(code, "/app/routes/users.js", rules.LangJavaScript)
	if flowMatchesSinkID(flows, "js.neo4j.session.run") {
		t.Error("expected NO js.neo4j.session.run flow for parameterized session.run() (literal Cypher + params object)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Safe: hardcoded Cypher literal (no user input at all) ---

func TestJS_Neo4j_Driver_ExecuteQuery_Hardcoded_NoFlow(t *testing.T) {
	code := `
function countUsers() {
    return driver.executeQuery("MATCH (u:User) RETURN count(u)");
}
`
	flows := Analyze(code, "/app/lib/metrics.js", rules.LangJavaScript)
	if flowMatchesSinkID(flows, "js.neo4j.driver.executequery") {
		t.Error("expected NO js.neo4j.driver.executequery flow for hardcoded Cypher literal")
	}
}

// flowMatchesSinkID returns true if any flow's sink has the given ID.
func flowMatchesSinkID(flows []taint.TaintFlow, id string) bool {
	for _, f := range flows {
		if f.Sink.ID == id {
			return true
		}
	}
	return false
}
