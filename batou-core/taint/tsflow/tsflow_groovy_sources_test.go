package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
)

// Tests for Groovy source catalog entries added in this cycle:
// GORM database results, Grails request methods, Groovy I/O patterns.

func TestGroovy_GORMCreateCriteriaToSQLInjection(t *testing.T) {
	// GORM criteria query result used in raw SQL
	code := `
def handler() {
    def results = User.createCriteria()
    sql.execute("DELETE FROM audit WHERE user = '" + results + "'")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for GORM createCriteria result -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_GORMFindWhereToSQLInjection(t *testing.T) {
	// GORM findWhere result used in raw SQL
	code := `
def handler() {
    def user = User.findWhere(name: "admin")
    sql.execute("SELECT * FROM orders WHERE owner = '" + user + "'")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for GORM findWhere result -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_GORMExecuteQueryToCommand(t *testing.T) {
	// GORM HQL result used in command execution
	code := `
def handler() {
    def result = User.executeQuery("FROM User WHERE id = 1")
    Runtime.getRuntime().exec("notify " + result)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for GORM executeQuery result -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_RequestInputStreamToSQLInjection(t *testing.T) {
	// Grails request input stream used in raw SQL
	code := `
def handler(request) {
    def body = request.getInputStream().text
    sql.execute("INSERT INTO logs VALUES ('" + body + "')")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for request.getInputStream -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_RequestXMLToSQLInjection(t *testing.T) {
	// Grails XML request body used in raw SQL
	code := `
def handler(request) {
    def data = request.XML
    sql.execute("SELECT * FROM users WHERE name = '" + data + "'")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for request.XML -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_ProcessExecuteTextToCommand(t *testing.T) {
	// Groovy process output used in another command (2nd-order injection)
	code := `
def handler() {
    def output = "hostname".execute().text
    Runtime.getRuntime().exec("ping " + output)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for process.execute().text -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_ConsoleReadLineToSQLInjection(t *testing.T) {
	// Console readline used in raw SQL
	code := `
def handler() {
    def input = System.console().readLine("Enter name: ")
    sql.execute("SELECT * FROM users WHERE name = '" + input + "'")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for System.console().readLine -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
