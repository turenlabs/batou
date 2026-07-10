package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// JPA / Hibernate / Doctrine EntityManager receiver-alias recall-FN tests.
//
// The canonical JPA persistence-context variable is `em` (Spring's
// `@PersistenceContext EntityManager em`) or `entityManager`; Doctrine uses
// `$em`. None of these is a prefix of "entitymanager" (the abbreviation `em`
// diverges at the 2nd character) and `em` is unrelated to "session", so before
// the matcher alias the tsflow structural matcher could not associate
// `em.createNativeQuery(sql)` / `$em->createQuery(dql)` with their catalog
// SQL-injection sinks (or `em.find(...)` with the JPA second-order source) even
// though the catalog Patterns explicitly list `entityManager`. Only the
// non-idiomatic `session` (Hibernate) / `$em`-as-prefix spellings fired.
//
// These exercise the idiomatic receiver names that real JPA/Doctrine code uses.

func flowHasSinkID(flows []taint.TaintFlow, id string) bool {
	for _, f := range flows {
		if f.Sink.ID == id {
			return true
		}
	}
	return false
}

func flowHasSourceID(flows []taint.TaintFlow, id string) bool {
	for _, f := range flows {
		if f.Source.ID == id {
			return true
		}
	}
	return false
}

// --- Java: Hibernate/JPA query sinks reached via `em` / `entityManager` ---

func TestJPA_Java_EntityManagerNativeQuery(t *testing.T) {
	for _, recv := range []string{"em", "entityManager", "this.em"} {
		code := `
public class UserDao {
  public void search(javax.servlet.http.HttpServletRequest request,
                     javax.persistence.EntityManager em) throws Exception {
    String name = request.getParameter("name");
    ` + recv + `.createNativeQuery("SELECT * FROM users WHERE name = '" + name + "'");
  }
}`
		flows := Analyze(code, "/app/UserDao.java", rules.LangJava)
		if !flowHasSinkID(flows, "java.hibernate.createnativequery") {
			t.Errorf("receiver %q: expected java.hibernate.createnativequery SQL-injection flow, got %d flows", recv, len(flows))
		}
	}
}

func TestJPA_Java_EntityManagerCreateQueryHQL(t *testing.T) {
	code := `
public class UserDao {
  public void search(javax.servlet.http.HttpServletRequest request,
                     javax.persistence.EntityManager em) throws Exception {
    String name = request.getParameter("name");
    em.createQuery("FROM User WHERE name = '" + name + "'");
  }
}`
	flows := Analyze(code, "/app/UserDao.java", rules.LangJava)
	if !flowHasSinkID(flows, "java.hibernate.createquery") {
		t.Errorf("expected java.hibernate.createquery HQL-injection flow via em, got %d flows", len(flows))
	}
}

func TestJPA_Java_HibernateSessionStillFires(t *testing.T) {
	// Regression guard: the canonical Hibernate `session` receiver must keep
	// firing (the alias is additive, not a replacement).
	code := `
public class UserDao {
  public void search(javax.servlet.http.HttpServletRequest request,
                     org.hibernate.Session session) throws Exception {
    String name = request.getParameter("name");
    session.createNativeQuery("SELECT * FROM users WHERE name = '" + name + "'");
  }
}`
	flows := Analyze(code, "/app/UserDao.java", rules.LangJava)
	if !flowHasSinkID(flows, "java.hibernate.createnativequery") {
		t.Errorf("expected java.hibernate.createnativequery flow via session, got %d flows", len(flows))
	}
}

func TestJPA_Java_EntityManagerFindSecondOrderSource(t *testing.T) {
	// em.find() returns DB-backed data — a second-order injection source.
	code := `
public class UserDao {
  public void run(javax.persistence.EntityManager em, java.sql.Statement stmt) throws Exception {
    Object u = em.find(User.class, 1);
    stmt.executeQuery("SELECT * FROM audit WHERE who = '" + u.toString() + "'");
  }
}`
	flows := Analyze(code, "/app/UserDao.java", rules.LangJava)
	if !flowHasSourceID(flows, "java.jpa.entitymanager.find") {
		t.Errorf("expected java.jpa.entitymanager.find second-order source via em, got %d flows", len(flows))
	}
}

func TestJPA_Java_ConstantQueryNoFlow(t *testing.T) {
	// Negative control: a constant native query carries no taint.
	code := `
public class UserDao {
  public void search(javax.persistence.EntityManager em) throws Exception {
    em.createNativeQuery("SELECT * FROM users WHERE id = 1");
  }
}`
	flows := Analyze(code, "/app/UserDao.java", rules.LangJava)
	if len(flows) != 0 {
		t.Errorf("expected 0 flows for constant native query, got %d", len(flows))
	}
}

// --- PHP: Doctrine ORM query sinks reached via `$em` / `$entityManager` ---

func TestJPA_PHP_DoctrineEntityManager(t *testing.T) {
	for _, recv := range []string{"$em", "$entityManager"} {
		code := `<?php
function search() {
  $name = $_GET['name'];
  ` + recv + `->createQuery("SELECT u FROM App\\Entity\\User u WHERE u.name = '" . $name . "'");
}`
		flows := Analyze(code, "/app/search.php", rules.LangPHP)
		if !flowHasSinkID(flows, "php.doctrine.dqlquery") {
			t.Errorf("receiver %q: expected php.doctrine.dqlquery DQL-injection flow, got %d flows", recv, len(flows))
		}
	}
}

func TestJPA_PHP_DoctrineConstantNoFlow(t *testing.T) {
	code := `<?php
function search() {
  $em->createQuery("SELECT u FROM App\\Entity\\User u WHERE u.active = 1");
}`
	flows := Analyze(code, "/app/search.php", rules.LangPHP)
	if len(flows) != 0 {
		t.Errorf("expected 0 flows for constant DQL, got %d", len(flows))
	}
}

// --- Kotlin: JPA query sinks reached via `em` ---

func TestJPA_Kotlin_EntityManagerNativeQuery(t *testing.T) {
	code := `
fun search(req: javax.servlet.http.HttpServletRequest, em: javax.persistence.EntityManager) {
    val name = req.getParameter("name")
    em.createNativeQuery("SELECT * FROM users WHERE name = '" + name + "'")
}`
	flows := Analyze(code, "/app/Search.kt", rules.LangKotlin)
	if !flowHasSinkID(flows, "kotlin.jpa.createnativequery") {
		t.Errorf("expected kotlin.jpa.createnativequery flow via em, got %d flows", len(flows))
	}
}

func TestJPA_Kotlin_ConstantNoFlow(t *testing.T) {
	// `em` is an injected field (the realistic JPA/Spring shape), so it is not
	// a function parameter — the Kotlin walker's broad param-seeding does not
	// apply, and a constant native query carries no taint.
	code := `
class UserDao(val em: javax.persistence.EntityManager) {
    fun search() {
        em.createNativeQuery("SELECT * FROM users WHERE id = 1")
    }
}`
	flows := Analyze(code, "/app/Search.kt", rules.LangKotlin)
	if len(flows) != 0 {
		t.Errorf("expected 0 flows for constant native query, got %d", len(flows))
	}
}
