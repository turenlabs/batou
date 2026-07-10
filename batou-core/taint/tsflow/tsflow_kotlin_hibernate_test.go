package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Tests for Kotlin Hibernate-native Session HQL/SQL injection sinks (CWE-89).
//
// The pre-existing kotlin.jpa.createquery / kotlin.jpa.createnativequery
// entries key on ObjectType "EntityManager", so the tsflow matcher only fires
// for receivers like `entityManager`/`em`. Hibernate's native API is reached
// through an org.hibernate.Session (receiver `session`), which does NOT
// prefix-match "EntityManager" — so `session.createQuery(...)` produced no SQL
// sink before these entries were added. createSQLQuery is Hibernate-only and
// has no JPA EntityManager equivalent at all.
//
// Note: createQuery/createNativeQuery/createSQLQuery all contain the substring
// "Query(", which trips isWebHandlerFunc's auto-taint of handler parameters.
// Every handler below therefore takes NO parameters and seeds taint from
// readLine(), so the auto-taint has nothing to act on (and the negative tests
// stay clean).

// --- Session.createQuery (HQL injection) ---

func TestKotlin_Hibernate_Session_CreateQuery_Injection(t *testing.T) {
	code := `
fun handler() {
    val name = readLine()
    val hql = "FROM User u WHERE u.name = '" + name + "'"
    session.createQuery(hql)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected HQL-injection flow for readLine -> session.createQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Session.createNativeQuery (raw SQL injection) ---

func TestKotlin_Hibernate_Session_CreateNativeQuery_Injection(t *testing.T) {
	code := `
fun handler() {
    val id = readLine()
    val sql = "SELECT * FROM users WHERE id = " + id
    session.createNativeQuery(sql)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL-injection flow for readLine -> session.createNativeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Session.createSQLQuery (legacy Hibernate native SQL injection) ---

func TestKotlin_Hibernate_Session_CreateSQLQuery_Injection(t *testing.T) {
	code := `
fun handler() {
    val order = readLine()
    val sql = "SELECT * FROM products ORDER BY " + order
    session.createSQLQuery(sql)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL-injection flow for readLine -> session.createSQLQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Safe: parameterized HQL (literal query + named parameter) ---

func TestKotlin_Hibernate_Session_CreateQuery_Parameterized_NoFlow(t *testing.T) {
	code := `
fun handler() {
    val name = readLine()
    val q = session.createQuery("FROM User u WHERE u.name = :name")
    q.setParameter("name", name)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NO injection flow when HQL is a literal and values are bound via setParameter")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Safe: hardcoded native SQL ---

func TestKotlin_Hibernate_Session_CreateNativeQuery_Hardcoded_NoFlow(t *testing.T) {
	code := `
fun handler() {
    session.createNativeQuery("SELECT * FROM users WHERE active = 1")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NO injection flow for hardcoded native SQL literal")
	}
}
