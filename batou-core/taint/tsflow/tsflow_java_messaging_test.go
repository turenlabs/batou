package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// --- JMS TextMessage (CWE-89) ---

func TestJava_JMS_TextMessage_SQLInjection(t *testing.T) {
	code := `
import javax.jms.*;
import java.sql.*;

public class OrderProcessor implements MessageListener {
    private Connection dbConn;

    public void onMessage(Message message) {
        TextMessage textMessage = (TextMessage) message;
        String orderId = textMessage.getText();
        Statement stmt = dbConn.createStatement();
        stmt.executeQuery("SELECT * FROM orders WHERE id = '" + orderId + "'");
    }
}
`
	flows := Analyze(code, "/app/OrderProcessor.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for JMS TextMessage.getText() -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- JMS ObjectMessage deserialization (CWE-502) ---

func TestJava_JMS_ObjectMessage_CommandInjection(t *testing.T) {
	code := `
import javax.jms.*;

public class EventProcessor implements MessageListener {
    public void onMessage(Message message) {
        ObjectMessage objectMessage = (ObjectMessage) message;
        Object payload = objectMessage.getObject();
        String cmd = payload.toString();
        Runtime.getRuntime().exec(cmd);
    }
}
`
	flows := Analyze(code, "/app/EventProcessor.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for JMS ObjectMessage.getObject() -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- JMS MapMessage (CWE-89) ---

func TestJava_JMS_MapMessage_SQLInjection(t *testing.T) {
	code := `
import javax.jms.*;
import java.sql.*;

public class UserSync implements MessageListener {
    private Connection dbConn;

    public void onMessage(Message message) {
        MapMessage mapMessage = (MapMessage) message;
        String username = mapMessage.getString("username");
        Statement stmt = dbConn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + username + "'");
    }
}
`
	flows := Analyze(code, "/app/UserSync.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for JMS MapMessage.getString() -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- JMS Message.getStringProperty (CWE-78) ---

func TestJava_JMS_MessageProperty_CommandInjection(t *testing.T) {
	code := `
import javax.jms.*;

public class TaskRunner implements MessageListener {
    public void onMessage(Message message) {
        String script = message.getStringProperty("script");
        Runtime.getRuntime().exec(script);
    }
}
`
	flows := Analyze(code, "/app/TaskRunner.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for JMS Message.getStringProperty() -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Kafka ConsumerRecord (CWE-78) ---

func TestJava_Kafka_ConsumerRecord_CommandInjection(t *testing.T) {
	code := `
import org.apache.kafka.clients.consumer.ConsumerRecord;

public class CommandConsumer {
    public void process(ConsumerRecord<String, String> consumerRecord) {
        String command = consumerRecord.value();
        Runtime.getRuntime().exec(command);
    }
}
`
	flows := Analyze(code, "/app/CommandConsumer.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for Kafka ConsumerRecord.value() -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Kafka ConsumerRecord.key (CWE-89) ---

func TestJava_Kafka_ConsumerRecord_Key_SQLInjection(t *testing.T) {
	code := `
import org.apache.kafka.clients.consumer.ConsumerRecord;
import java.sql.*;

public class KeyProcessor {
    private Connection conn;

    public void process(ConsumerRecord<String, String> consumerRecord) {
        String key = consumerRecord.key();
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM events WHERE key = '" + key + "'");
    }
}
`
	flows := Analyze(code, "/app/KeyProcessor.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Kafka ConsumerRecord.key() -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- RabbitMQ Delivery (CWE-79) ---

func TestJava_RabbitMQ_Delivery_SQLInjection(t *testing.T) {
	code := `
import com.rabbitmq.client.Delivery;
import java.sql.*;

public class NotificationHandler {
    private Connection conn;

    public void handle(Delivery delivery) throws Exception {
        byte[] data = delivery.getBody();
        String body = data.toString();
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM notifications WHERE body = '" + body + "'");
    }
}
`
	flows := Analyze(code, "/app/NotificationHandler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for RabbitMQ Delivery.getBody() -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Kafka ConsumerRecord safe with PreparedStatement ---

func TestJava_Kafka_Safe_PreparedStatement(t *testing.T) {
	code := `
import org.apache.kafka.clients.consumer.ConsumerRecord;
import java.sql.*;

public class SafeConsumer {
    private Connection conn;

    public void process(ConsumerRecord<String, String> consumerRecord) throws Exception {
        String value = consumerRecord.value();
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM events WHERE data = ?");
        ps.setString(1, value);
        ps.executeQuery();
    }
}
`
	flows := Analyze(code, "/app/SafeConsumer.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NO SQL injection flow when Kafka data goes through PreparedStatement")
	}
}

// --- JAX-RS @CookieParam (CWE-22) ---

func TestJava_JAXRS_CookieParam_PathTraversal(t *testing.T) {
	code := `
import javax.ws.rs.*;
import java.io.*;

@Path("/files")
public class FileResource {
    @GET
    public String readFile(@CookieParam("filename") String filename) throws Exception {
        FileInputStream fis = new FileInputStream("/data/" + filename);
        return new String(fis.readAllBytes());
    }
}
`
	flows := Analyze(code, "/app/FileResource.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected path traversal flow for @CookieParam -> FileInputStream")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
