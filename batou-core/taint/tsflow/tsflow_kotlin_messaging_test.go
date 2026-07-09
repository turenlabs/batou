package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// --- JMS TextMessage (CWE-89) ---

func TestKotlin_JMS_TextMessage_SQLInjection(t *testing.T) {
	code := `
import javax.jms.Message
import javax.jms.MessageListener
import javax.jms.TextMessage
import java.sql.Connection

class OrderProcessor(private val dbConn: Connection) : MessageListener {
    override fun onMessage(message: Message) {
        val textMessage = message as TextMessage
        val orderId = textMessage.getText()
        val stmt = dbConn.createStatement()
        stmt.executeQuery("SELECT * FROM orders WHERE id = '" + orderId + "'")
    }
}
`
	flows := Analyze(code, "/app/OrderProcessor.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for JMS TextMessage.getText() -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- JMS ObjectMessage deserialization (CWE-78) ---

func TestKotlin_JMS_ObjectMessage_CommandInjection(t *testing.T) {
	code := `
import javax.jms.Message
import javax.jms.MessageListener
import javax.jms.ObjectMessage

class EventProcessor : MessageListener {
    override fun onMessage(message: Message) {
        val objectMessage = message as ObjectMessage
        val payload = objectMessage.getObject()
        val cmd = payload.toString()
        Runtime.getRuntime().exec(cmd)
    }
}
`
	flows := Analyze(code, "/app/EventProcessor.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for JMS ObjectMessage.getObject() -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- JMS MapMessage (CWE-89) ---

func TestKotlin_JMS_MapMessage_SQLInjection(t *testing.T) {
	code := `
import javax.jms.MapMessage
import javax.jms.Message
import javax.jms.MessageListener
import java.sql.Connection

class UserSync(private val dbConn: Connection) : MessageListener {
    override fun onMessage(message: Message) {
        val mapMessage = message as MapMessage
        val username = mapMessage.getString("username")
        val stmt = dbConn.createStatement()
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + username + "'")
    }
}
`
	flows := Analyze(code, "/app/UserSync.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for JMS MapMessage.getString() -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Kafka ConsumerRecord (CWE-78) ---

func TestKotlin_Kafka_ConsumerRecord_CommandInjection(t *testing.T) {
	code := `
import org.apache.kafka.clients.consumer.ConsumerRecord

class CommandConsumer {
    fun process(consumerRecord: ConsumerRecord<String, String>) {
        val command = consumerRecord.value()
        Runtime.getRuntime().exec(command)
    }
}
`
	flows := Analyze(code, "/app/CommandConsumer.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for Kafka ConsumerRecord.value() -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Kafka ConsumerRecord.key (CWE-89) ---

func TestKotlin_Kafka_ConsumerRecord_Key_SQLInjection(t *testing.T) {
	code := `
import org.apache.kafka.clients.consumer.ConsumerRecord
import java.sql.Connection

class KeyProcessor(private val conn: Connection) {
    fun process(consumerRecord: ConsumerRecord<String, String>) {
        val key = consumerRecord.key()
        val stmt = conn.createStatement()
        stmt.executeQuery("SELECT * FROM events WHERE key = '" + key + "'")
    }
}
`
	flows := Analyze(code, "/app/KeyProcessor.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Kafka ConsumerRecord.key() -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- RabbitMQ Delivery (CWE-89) ---

func TestKotlin_RabbitMQ_Delivery_SQLInjection(t *testing.T) {
	code := `
import com.rabbitmq.client.Delivery
import java.sql.Connection

class NotificationHandler(private val conn: Connection) {
    fun handle(delivery: Delivery) {
        val data = delivery.getBody()
        val body = String(data)
        val stmt = conn.createStatement()
        stmt.executeQuery("SELECT * FROM notifications WHERE body = '" + body + "'")
    }
}
`
	flows := Analyze(code, "/app/NotificationHandler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for RabbitMQ Delivery.getBody() -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Micronaut @QueryValue annotation (CWE-89) ---

func TestKotlin_Micronaut_QueryValue_SQLInjection(t *testing.T) {
	code := `
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.QueryValue
import java.sql.Connection

@Controller("/users")
class UserController(private val conn: Connection) {
    @Get("/search")
    fun search(@QueryValue name: String): String {
        val stmt = conn.createStatement()
        val rs = stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'")
        return rs.toString()
    }
}
`
	flows := Analyze(code, "/app/UserController.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Micronaut @QueryValue -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Micronaut HttpRequest.getBody (CWE-78) ---

func TestKotlin_Micronaut_HttpRequestBody_CommandInjection(t *testing.T) {
	code := `
import io.micronaut.http.HttpRequest
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Post

@Controller("/admin")
class AdminController {
    @Post("/run")
    fun runCommand(httpRequest: HttpRequest<String>) {
        val body = httpRequest.getBody()
        val cmd = body.toString()
        Runtime.getRuntime().exec(cmd)
    }
}
`
	flows := Analyze(code, "/app/AdminController.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for Micronaut HttpRequest.getBody() -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Kafka safe with PreparedStatement ---

func TestKotlin_Kafka_Safe_PreparedStatement(t *testing.T) {
	code := `
import org.apache.kafka.clients.consumer.ConsumerRecord
import java.sql.Connection

class SafeConsumer(private val conn: Connection) {
    fun process(consumerRecord: ConsumerRecord<String, String>) {
        val value = consumerRecord.value()
        val ps = conn.prepareStatement("SELECT * FROM events WHERE data = ?")
        ps.setString(1, value)
        ps.executeQuery()
    }
}
`
	flows := Analyze(code, "/app/SafeConsumer.kt", rules.LangKotlin)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NO SQL injection flow when Kafka data goes through PreparedStatement")
	}
}

// --- Spring @KafkaListener (CWE-89) ---

func TestKotlin_Spring_KafkaListener_SQLInjection(t *testing.T) {
	code := `
import org.springframework.kafka.annotation.KafkaListener
import java.sql.Connection

class EventConsumer(private val conn: Connection) {
    @KafkaListener(topics = ["events"])
    fun consume(payload: String) {
        val stmt = conn.createStatement()
        stmt.executeQuery("SELECT * FROM events WHERE data = '" + payload + "'")
    }
}
`
	flows := Analyze(code, "/app/EventConsumer.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for @KafkaListener -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
