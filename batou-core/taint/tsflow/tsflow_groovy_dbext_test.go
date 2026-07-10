package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
)

// Tests for Groovy database sources (JDBC, GORM, JPA) and external
// integration sources (Camel, JMS, AMQP, Kafka) added in PR #279.

// ---------------------------------------------------------------------------
// JDBC ResultSet sources
// ---------------------------------------------------------------------------

func TestGroovy_ResultSetGetStringToSQLInjection(t *testing.T) {
	code := `
def handler() {
    def rs = stmt.executeQuery("SELECT name FROM users WHERE id = 1")
    def name = rs.getString("name")
    sql.execute("SELECT * FROM logs WHERE author = '" + name + "'")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for ResultSet.getString -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_ResultSetGetObjectToCommand(t *testing.T) {
	code := `
def handler() {
    def rs = stmt.executeQuery("SELECT cmd FROM jobs WHERE id = 1")
    def cmd = rs.getObject("cmd")
    Runtime.getRuntime().exec("sh -c " + cmd)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for ResultSet.getObject -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_ResultSetGetIntToSQLInjection(t *testing.T) {
	code := `
def handler() {
    def rs = stmt.executeQuery("SELECT priority FROM tasks")
    def priority = rs.getInt("priority")
    sql.execute("SELECT * FROM tasks WHERE priority = " + priority)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for ResultSet.getInt -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ---------------------------------------------------------------------------
// GORM additional methods
// ---------------------------------------------------------------------------

func TestGroovy_GORMGetAllToSQLInjection(t *testing.T) {
	code := `
def handler() {
    def users = User.getAll([1, 2, 3])
    sql.execute("INSERT INTO report VALUES ('" + users + "')")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for GORM getAll -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_GORMFindAllWhereToSQLInjection(t *testing.T) {
	code := `
def handler() {
    def users = User.findAllWhere(active: true)
    sql.execute("DELETE FROM audit WHERE user IN ('" + users + "')")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for GORM findAllWhere -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_GORMWithCriteriaToCommand(t *testing.T) {
	code := `
def handler() {
    def result = User.withCriteria { eq("role", "admin") }
    Runtime.getRuntime().exec("notify " + result)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for GORM withCriteria -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ---------------------------------------------------------------------------
// JPA sources
// ---------------------------------------------------------------------------

func TestGroovy_JPAEntityManagerFindToSQLInjection(t *testing.T) {
	code := `
def handler() {
    def user = entityManager.find(User.class, 1L)
    sql.execute("SELECT * FROM audit WHERE user_name = '" + user + "'")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for EntityManager.find -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_JPAQueryResultListToCommand(t *testing.T) {
	code := `
def handler() {
    def results = query.getResultList()
    Runtime.getRuntime().exec("process " + results)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for TypedQuery.getResultList -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ---------------------------------------------------------------------------
// External integration sources
// ---------------------------------------------------------------------------

func TestGroovy_CamelExchangeBodyToCommand(t *testing.T) {
	code := `
def handler(exchange) {
    def body = exchange.getIn().getBody(String.class)
    Runtime.getRuntime().exec("process " + body)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for Camel Exchange.getBody -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_JMSTextMessageToSQLInjection(t *testing.T) {
	code := `
def onMessage(message) {
    def text = message.getText()
    sql.execute("INSERT INTO events VALUES ('" + text + "')")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for JMS TextMessage.getText -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_SpringAMQPMessageBodyToSQLInjection(t *testing.T) {
	code := `
def handleMessage(message) {
    def payload = message.getBody()
    sql.execute("INSERT INTO queue_data VALUES ('" + payload + "')")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for AMQP Message.getBody -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_KafkaConsumerRecordToSQLInjection(t *testing.T) {
	code := `
def consume(record) {
    def val = record.value()
    sql.execute("INSERT INTO events VALUES ('" + val + "')")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Kafka ConsumerRecord.value -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ---------------------------------------------------------------------------
// Negative test — sanitized data should NOT produce taint flow
// ---------------------------------------------------------------------------

func TestGroovy_ResultSetGetString_Parameterized_NoFlow(t *testing.T) {
	// Data from DB is used in a parameterized query — no SQL injection
	code := `
def handler() {
    def rs = stmt.executeQuery("SELECT name FROM users WHERE id = 1")
    def name = rs.getString("name")
    def safe = Integer.parseInt(name)
    sql.execute("SELECT * FROM logs WHERE author_id = " + safe)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Error("expected NO SQL injection flow when ResultSet data is sanitized via parseInt")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
