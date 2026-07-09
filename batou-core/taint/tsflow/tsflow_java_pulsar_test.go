package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Apache Pulsar consumer sources (CWE-89 / CWE-78 / CWE-79).
// Pulsar messages carry attacker-controlled payloads from upstream producers.
// In multi-tenant clusters, IoT pipelines, and cross-team topics the consumer
// must treat every Message field as untrusted — same threat model as Kafka
// ConsumerRecord and RabbitMQ Delivery, both of which already have catalog
// coverage. Org reference: org.apache.pulsar.client.api.{Consumer,Reader,Message}.

// --- Pulsar Message.getValue() -> SQL injection (CWE-89) ---

func TestJava_Pulsar_Message_GetValue_SQLInjection(t *testing.T) {
	code := `
import org.apache.pulsar.client.api.Consumer;
import org.apache.pulsar.client.api.Message;
import java.sql.*;

public class OrderConsumer {
    private Connection conn;

    public void process(Consumer<String> consumer) throws Exception {
        Message<String> message = consumer.receive();
        String orderId = message.getValue();
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM orders WHERE id = '" + orderId + "'");
    }
}
`
	flows := Analyze(code, "/app/OrderConsumer.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Pulsar Message.getValue() -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Pulsar Message.getData() -> command injection (CWE-78) ---

func TestJava_Pulsar_Message_GetData_CommandInjection(t *testing.T) {
	code := `
import org.apache.pulsar.client.api.Consumer;
import org.apache.pulsar.client.api.Message;

public class CommandConsumer {
    public void process(Consumer<byte[]> consumer) throws Exception {
        Message<byte[]> message = consumer.receive();
        byte[] data = message.getData();
        String cmd = new String(data);
        Runtime.getRuntime().exec(cmd);
    }
}
`
	flows := Analyze(code, "/app/CommandConsumer.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for Pulsar Message.getData() -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Pulsar Message.getKey() -> SQL injection (CWE-89) ---

func TestJava_Pulsar_Message_GetKey_SQLInjection(t *testing.T) {
	code := `
import org.apache.pulsar.client.api.Consumer;
import org.apache.pulsar.client.api.Message;
import java.sql.*;

public class KeyProcessor {
    private Connection conn;

    public void process(Consumer<String> consumer) throws Exception {
        Message<String> message = consumer.receive();
        String key = message.getKey();
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM events WHERE key = '" + key + "'");
    }
}
`
	flows := Analyze(code, "/app/KeyProcessor.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Pulsar Message.getKey() -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Pulsar Message.getProperty() -> command injection (CWE-78) ---

func TestJava_Pulsar_Message_GetProperty_CommandInjection(t *testing.T) {
	code := `
import org.apache.pulsar.client.api.Consumer;
import org.apache.pulsar.client.api.Message;

public class ScriptRunner {
    public void process(Consumer<String> consumer) throws Exception {
        Message<String> message = consumer.receive();
        String script = message.getProperty("script");
        Runtime.getRuntime().exec(script);
    }
}
`
	flows := Analyze(code, "/app/ScriptRunner.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for Pulsar Message.getProperty() -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- @PulsarListener parameter -> SQL injection (CWE-89) ---

func TestJava_Spring_PulsarListener_SQLInjection(t *testing.T) {
	code := `
import org.springframework.pulsar.annotation.PulsarListener;
import java.sql.*;

public class TopicHandler {
    private Connection conn;

    @PulsarListener(topics = "users")
    public void handle(String userId) throws Exception {
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM accounts WHERE user_id = '" + userId + "'");
    }
}
`
	flows := Analyze(code, "/app/TopicHandler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for @PulsarListener param -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Pulsar Message safe with PreparedStatement (negative case) ---

func TestJava_Pulsar_Message_Safe_PreparedStatement(t *testing.T) {
	code := `
import org.apache.pulsar.client.api.Consumer;
import org.apache.pulsar.client.api.Message;
import java.sql.*;

public class SafeConsumer {
    private Connection conn;

    public void process(Consumer<String> consumer) throws Exception {
        Message<String> message = consumer.receive();
        String value = message.getValue();
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM events WHERE data = ?");
        ps.setString(1, value);
        ps.executeQuery();
    }
}
`
	flows := Analyze(code, "/app/SafeConsumer.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NO SQL injection flow when Pulsar payload goes through PreparedStatement")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}
