package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Apache Camel integration framework taint sources. The Exchange / Message /
// ConsumerTemplate APIs are the canonical taint boundaries inside Camel
// processors and route DSL beans — body, headers, and exchange properties all
// originate from external endpoints (HTTP/JMS/Kafka/file/etc.) and are
// attacker-controlled when the route consumes from an untrusted endpoint.
//
// Tests intentionally use intermediate variable assignments rather than
// chained .getIn().getBody() calls combined with explicit casts: the tsflow
// walker propagates taint through assignments and through method calls on
// tainted receivers, but does not currently see through a cast that wraps a
// source-call expression. Real Camel code uses both styles; the catalog
// matches in both shapes via tainted-receiver propagation, the tests pin
// down the assignment shape since that's what the walker can verify.

// --- Exchange.getIn() then Message.getBody() → SQL injection (CWE-89) ---

func TestJava_Camel_ExchangeGetInBody_SQLInjection(t *testing.T) {
	code := `
import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.apache.camel.Processor;
import java.sql.*;

public class OrderRouter implements Processor {
    private Connection conn;

    public void process(Exchange exchange) throws Exception {
        Message message = exchange.getIn();
        Object orderId = message.getBody();
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM orders WHERE id = '" + orderId + "'");
    }
}
`
	flows := Analyze(code, "/app/OrderRouter.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Camel Exchange.getIn() body -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Exchange.getMessage() (modern Camel 3.x API) → command injection ---

func TestJava_Camel_ExchangeGetMessageBody_CommandInjection(t *testing.T) {
	code := `
import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.apache.camel.Processor;

public class CommandRouter implements Processor {
    public void process(Exchange exchange) throws Exception {
        Message message = exchange.getMessage();
        Object cmd = message.getBody();
        Runtime.getRuntime().exec(cmd.toString());
    }
}
`
	flows := Analyze(code, "/app/CommandRouter.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for Camel Exchange.getMessage() body -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Exchange.getProperty(...) → SQL injection ---

func TestJava_Camel_ExchangeGetProperty_SQLInjection(t *testing.T) {
	code := `
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import java.sql.*;

public class TenantRouter implements Processor {
    private Connection conn;

    public void process(Exchange exchange) throws Exception {
        Object tenant = exchange.getProperty("tenantId");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM events WHERE tenant = '" + tenant + "'");
    }
}
`
	flows := Analyze(code, "/app/TenantRouter.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Camel Exchange.getProperty -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Exchange.getProperties() returning header map → SQL injection ---

func TestJava_Camel_ExchangeGetProperties_SQLInjection(t *testing.T) {
	code := `
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import java.sql.*;
import java.util.Map;

public class PropsRouter implements Processor {
    private Connection conn;

    public void process(Exchange exchange) throws Exception {
        Map<String, Object> props = exchange.getProperties();
        Object tenant = props.get("tenantId");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM events WHERE tenant = '" + tenant + "'");
    }
}
`
	flows := Analyze(code, "/app/PropsRouter.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Camel Exchange.getProperties -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Message.getHeader(...) → command injection ---

func TestJava_Camel_MessageGetHeader_CommandInjection(t *testing.T) {
	code := `
import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.apache.camel.Processor;

public class ScriptRouter implements Processor {
    public void process(Exchange exchange) throws Exception {
        Message message = exchange.getIn();
        Object script = message.getHeader("script");
        Runtime.getRuntime().exec(script.toString());
    }
}
`
	flows := Analyze(code, "/app/ScriptRouter.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for Camel Message.getHeader -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Message.getMandatoryBody → SQL injection ---

func TestJava_Camel_MessageGetMandatoryBody_SQLInjection(t *testing.T) {
	code := `
import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.apache.camel.Processor;
import java.sql.*;

public class StrictRouter implements Processor {
    private Connection conn;

    public void process(Exchange exchange) throws Exception {
        Message message = exchange.getIn();
        Object payload = message.getMandatoryBody();
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM payloads WHERE data = '" + payload + "'");
    }
}
`
	flows := Analyze(code, "/app/StrictRouter.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Camel Message.getMandatoryBody -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- ConsumerTemplate.receiveBody → SQL injection ---

func TestJava_Camel_ConsumerTemplateReceiveBody_SQLInjection(t *testing.T) {
	code := `
import org.apache.camel.ConsumerTemplate;
import java.sql.*;

public class FilePuller {
    private ConsumerTemplate consumerTemplate;
    private Connection conn;

    public void run() throws Exception {
        Object body = consumerTemplate.receiveBody("seda:files");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM uploads WHERE name = '" + body + "'");
    }
}
`
	flows := Analyze(code, "/app/FilePuller.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Camel ConsumerTemplate.receiveBody -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- ConsumerTemplate.receiveBodyNoWait → command injection ---

func TestJava_Camel_ConsumerTemplateReceiveBodyNoWait_CommandInjection(t *testing.T) {
	code := `
import org.apache.camel.ConsumerTemplate;

public class NoWaitPuller {
    private ConsumerTemplate consumerTemplate;

    public void run() throws Exception {
        Object cmd = consumerTemplate.receiveBodyNoWait("seda:cmds");
        Runtime.getRuntime().exec(cmd.toString());
    }
}
`
	flows := Analyze(code, "/app/NoWaitPuller.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for Camel ConsumerTemplate.receiveBodyNoWait -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- ConsumerTemplate.receive (returns Exchange) → SQL injection ---

func TestJava_Camel_ConsumerTemplateReceive_SQLInjection(t *testing.T) {
	code := `
import org.apache.camel.ConsumerTemplate;
import org.apache.camel.Exchange;
import org.apache.camel.Message;
import java.sql.*;

public class PullRouter {
    private ConsumerTemplate consumerTemplate;
    private Connection conn;

    public void run() throws Exception {
        Exchange exchange = consumerTemplate.receive("seda:in");
        Message message = exchange.getIn();
        Object data = message.getBody();
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM events WHERE data = '" + data + "'");
    }
}
`
	flows := Analyze(code, "/app/PullRouter.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Camel ConsumerTemplate.receive -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Exchange.getOut() (deprecated but still common) → command injection ---

func TestJava_Camel_ExchangeGetOut_CommandInjection(t *testing.T) {
	code := `
import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.apache.camel.Processor;

public class LegacyRouter implements Processor {
    public void process(Exchange exchange) throws Exception {
        Message message = exchange.getOut();
        Object tool = message.getBody();
        Runtime.getRuntime().exec(tool.toString());
    }
}
`
	flows := Analyze(code, "/app/LegacyRouter.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for Camel Exchange.getOut() body -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- PollingConsumer.receive → SQL injection ---

func TestJava_Camel_PollingConsumerReceive_SQLInjection(t *testing.T) {
	code := `
import org.apache.camel.PollingConsumer;
import org.apache.camel.Exchange;
import org.apache.camel.Message;
import java.sql.*;

public class PollerJob {
    private PollingConsumer pollingConsumer;
    private Connection conn;

    public void poll() throws Exception {
        Exchange exchange = pollingConsumer.receive(5000);
        Message message = exchange.getIn();
        Object body = message.getBody();
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM jobs WHERE body = '" + body + "'");
    }
}
`
	flows := Analyze(code, "/app/PollerJob.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Camel PollingConsumer.receive -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Negative test: PreparedStatement should NOT trigger flow even with Camel source ---

func TestJava_Camel_Safe_PreparedStatement(t *testing.T) {
	code := `
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import java.sql.*;

public class SafeRouter implements Processor {
    private Connection conn;

    public void process(Exchange exchange) throws Exception {
        Object orderId = exchange.getProperty("orderId");
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM orders WHERE id = ?");
        ps.setString(1, orderId.toString());
        ps.executeQuery();
    }
}
`
	flows := Analyze(code, "/app/SafeRouter.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NO SQL injection flow when Camel data goes through PreparedStatement")
	}
}

// --- Negative test: constant string should NOT trigger flow (over-broadness regression) ---

func TestJava_Camel_Safe_ConstantString(t *testing.T) {
	code := `
import java.sql.*;

public class HardcodedQuery {
    private Connection conn;

    public void run() throws Exception {
        String hardcoded = "system";
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + hardcoded + "'");
    }
}
`
	flows := Analyze(code, "/app/HardcodedQuery.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NO flow for constant string concatenation (no Camel source involved)")
	}
}
