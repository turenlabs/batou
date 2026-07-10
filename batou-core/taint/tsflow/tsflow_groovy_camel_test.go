package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Apache Camel integration framework taint sources for Groovy. The Exchange /
// Message / ConsumerTemplate APIs are JVM-class identical between Java and
// Groovy — Groovy DSL routes, Camel processors written as Groovy classes, and
// Grails apps using Camel for messaging all read body, headers, and exchange
// properties from external endpoints (HTTP/JMS/Kafka/file/SEDA/etc.).
//
// Tests use intermediate variable assignments rather than chained
// `.getIn().getBody()` shapes: the tsflow walker propagates taint through
// assignments and through method calls on tainted receivers, and the
// assignment shape is what the matcher reliably verifies. Real Groovy Camel
// code uses both styles (explicit getters AND the property-access
// shorthand `exchange.in.body`); the catalog matches the explicit form
// used here, and idiomatic shortened forms still pick up taint via the
// existing `groovy.camel.exchange.body` chain entry.

// --- Exchange.getIn() then Message.getBody() → SQL injection (CWE-89) ---

func TestGroovy_Camel_ExchangeGetInBody_SQLInjection(t *testing.T) {
	code := `
def process(exchange) {
    def message = exchange.getIn()
    def orderId = message.getBody()
    sql.execute("SELECT * FROM orders WHERE id = '" + orderId + "'")
}
`
	flows := Analyze(code, "/app/OrderRouter.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Camel Exchange.getIn() body -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Exchange.getMessage() (modern Camel 3.x API) → command injection ---

func TestGroovy_Camel_ExchangeGetMessageBody_CommandInjection(t *testing.T) {
	code := `
def process(exchange) {
    def message = exchange.getMessage()
    def cmd = message.getBody()
    Runtime.getRuntime().exec(cmd.toString())
}
`
	flows := Analyze(code, "/app/CommandRouter.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for Camel Exchange.getMessage() body -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Exchange.getProperty(...) → SQL injection ---

func TestGroovy_Camel_ExchangeGetProperty_SQLInjection(t *testing.T) {
	code := `
def process(exchange) {
    def tenant = exchange.getProperty("tenantId")
    sql.execute("SELECT * FROM events WHERE tenant = '" + tenant + "'")
}
`
	flows := Analyze(code, "/app/TenantRouter.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Camel Exchange.getProperty -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Exchange.getProperties() returning property map → SQL injection ---

func TestGroovy_Camel_ExchangeGetProperties_SQLInjection(t *testing.T) {
	code := `
def process(exchange) {
    def props = exchange.getProperties()
    def tenant = props.get("tenantId")
    sql.execute("SELECT * FROM events WHERE tenant = '" + tenant + "'")
}
`
	flows := Analyze(code, "/app/PropsRouter.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Camel Exchange.getProperties -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Message.getHeader(...) → command injection ---

func TestGroovy_Camel_MessageGetHeader_CommandInjection(t *testing.T) {
	code := `
def process(exchange) {
    def message = exchange.getIn()
    def script = message.getHeader("script")
    Runtime.getRuntime().exec(script.toString())
}
`
	flows := Analyze(code, "/app/ScriptRouter.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for Camel Message.getHeader -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Message.getHeaders() → SQL injection ---

func TestGroovy_Camel_MessageGetHeaders_SQLInjection(t *testing.T) {
	code := `
def process(exchange) {
    def message = exchange.getIn()
    def headers = message.getHeaders()
    def tenant = headers.get("X-Tenant")
    sql.execute("SELECT * FROM events WHERE tenant = '" + tenant + "'")
}
`
	flows := Analyze(code, "/app/HeadersRouter.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Camel Message.getHeaders -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Message.getMandatoryBody → SQL injection ---

func TestGroovy_Camel_MessageGetMandatoryBody_SQLInjection(t *testing.T) {
	code := `
def process(exchange) {
    def message = exchange.getIn()
    def payload = message.getMandatoryBody()
    sql.execute("SELECT * FROM payloads WHERE data = '" + payload + "'")
}
`
	flows := Analyze(code, "/app/StrictRouter.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Camel Message.getMandatoryBody -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- ConsumerTemplate.receiveBody → SQL injection ---

func TestGroovy_Camel_ConsumerTemplateReceiveBody_SQLInjection(t *testing.T) {
	code := `
def runJob(consumerTemplate) {
    def body = consumerTemplate.receiveBody("seda:files")
    sql.execute("SELECT * FROM uploads WHERE name = '" + body + "'")
}
`
	flows := Analyze(code, "/app/FilePuller.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Camel ConsumerTemplate.receiveBody -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- ConsumerTemplate.receiveBodyNoWait → command injection ---

func TestGroovy_Camel_ConsumerTemplateReceiveBodyNoWait_CommandInjection(t *testing.T) {
	code := `
def runJob(consumerTemplate) {
    def cmd = consumerTemplate.receiveBodyNoWait("seda:cmds")
    Runtime.getRuntime().exec(cmd.toString())
}
`
	flows := Analyze(code, "/app/NoWaitPuller.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for Camel ConsumerTemplate.receiveBodyNoWait -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- ConsumerTemplate.receive (returns Exchange) → SQL injection ---

func TestGroovy_Camel_ConsumerTemplateReceive_SQLInjection(t *testing.T) {
	code := `
def runJob(consumerTemplate) {
    def exchange = consumerTemplate.receive("seda:in")
    def message = exchange.getIn()
    def data = message.getBody()
    sql.execute("SELECT * FROM events WHERE data = '" + data + "'")
}
`
	flows := Analyze(code, "/app/PullRouter.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Camel ConsumerTemplate.receive -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Exchange.getOut() (deprecated but still common) → command injection ---

func TestGroovy_Camel_ExchangeGetOut_CommandInjection(t *testing.T) {
	code := `
def process(exchange) {
    def message = exchange.getOut()
    def tool = message.getBody()
    Runtime.getRuntime().exec(tool.toString())
}
`
	flows := Analyze(code, "/app/LegacyRouter.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for Camel Exchange.getOut() body -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- PollingConsumer.receive → SQL injection ---

func TestGroovy_Camel_PollingConsumerReceive_SQLInjection(t *testing.T) {
	code := `
def poll(pollingConsumer) {
    def exchange = pollingConsumer.receive(5000)
    def message = exchange.getIn()
    def body = message.getBody()
    sql.execute("SELECT * FROM jobs WHERE body = '" + body + "'")
}
`
	flows := Analyze(code, "/app/PollerJob.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Camel PollingConsumer.receive -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Negative test: constant string should NOT trigger flow (over-broadness regression) ---

func TestGroovy_Camel_Safe_ConstantString(t *testing.T) {
	code := `
def runJob() {
    def hardcoded = "system"
    sql.execute("SELECT * FROM users WHERE name = '" + hardcoded + "'")
}
`
	flows := Analyze(code, "/app/HardcodedQuery.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NO flow for constant string concatenation (no Camel source involved)")
	}
}
