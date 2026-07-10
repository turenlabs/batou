package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Tests for Kotlin Neo4j Cypher injection sinks (CWE-943).
// Neo4j executes Cypher via Session/Transaction/Neo4jClient.run|query;
// if the Cypher string is built from user input (Kotlin string templates
// like "$name" expand to JVM-level concatenation), attackers can alter
// graph semantics. Safe code passes values as a Map<String, Any> argument.

// --- Neo4j direct driver: Session.run ---

func TestKotlin_Neo4j_Session_Run_Injection(t *testing.T) {
	code := `
fun handler() {
    val name = readLine()
    val cypher = "MATCH (n:User {name: '" + name + "'}) RETURN n"
    session.run(cypher)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Cypher-injection flow for readLine -> session.run")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Neo4j direct driver: Transaction.run (explicit begin/commit) ---

func TestKotlin_Neo4j_Tx_Run_Injection(t *testing.T) {
	code := `
fun handler() {
    val label = readLine()
    val cypher = "CREATE (:" + label + " {id: 1})"
    val tx = session.beginTransaction()
    tx.run(cypher)
    tx.commit()
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Cypher-injection flow for readLine -> tx.run")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Neo4j AsyncSession.runAsync ---

func TestKotlin_Neo4j_AsyncSession_RunAsync_Injection(t *testing.T) {
	code := `
fun handler() {
    val id = readLine()
    val cypher = "MATCH (n) WHERE id(n) = " + id + " RETURN n"
    asyncSession.runAsync(cypher)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Cypher-injection flow for readLine -> asyncSession.runAsync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Spring Data Neo4j: Neo4jClient.query ---

func TestKotlin_Neo4j_Neo4jClient_Query_Injection(t *testing.T) {
	code := `
fun handler() {
    val title = readLine()
    val cypher = "MATCH (p:Post) WHERE p.title = '" + title + "' RETURN p"
    neo4jClient.query(cypher)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Cypher-injection flow for readLine -> neo4jClient.query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Safe: parameterized Cypher (literal + params map) ---

func TestKotlin_Neo4j_Session_Run_Parameterized_NoFlow(t *testing.T) {
	code := `
fun handler() {
    val name = readLine()
    session.run("MATCH (n:User {name: \$name}) RETURN n", mapOf("name" to name))
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NO Cypher-injection flow when Cypher is a literal and values are passed via parameters map")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink pattern: %s)", f.Source.Category, f.Sink.Category, f.Sink.Pattern)
		}
	}
}

// --- Safe: hardcoded Cypher ---

func TestKotlin_Neo4j_Session_Run_Hardcoded_NoFlow(t *testing.T) {
	code := `
fun handler() {
    session.run("MATCH (n:User {name: 'bob'}) RETURN n")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NO Cypher-injection flow for hardcoded Cypher literal")
	}
}
