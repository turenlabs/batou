package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Java — Message broker / task-queue producer trust boundary (CWE-501)
// =========================================================================
//
// Producer side: a web handler pushes user-controlled values into a broker
// (Kafka / RabbitMQ / JMS). The payload is serialized into the broker and
// later deserialized + re-processed by a consumer in a privileged context.
// Tainted payload -> cross-boundary re-execution.
//
// Mirrors the Kotlin PR #421 producer-side sinks and the existing Python
// Celery/RQ (py.celery.apply_async, py.rq.enqueue) and Ruby Sidekiq/ActiveJob
// trust-boundary sinks. Java already had the consumer-side sources
// (Kafka ConsumerRecord.value, JMS TextMessage.getText,
// RabbitMQ Delivery.getBody, @KafkaListener/@JmsListener/@RabbitListener)
// but no producer-side sink until now.

func TestJava_TaskQueue_SpringKafkaTemplateSend(t *testing.T) {
	code := `
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OrderController {
    private final KafkaTemplate<String, String> kafkaTemplate;

    public OrderController(KafkaTemplate<String, String> kafkaTemplate) {
        this.kafkaTemplate = kafkaTemplate;
    }

    @PostMapping("/orders")
    public void createOrder(@RequestParam String payload) {
        kafkaTemplate.send("orders", payload);
    }
}
`
	flows := Analyze(code, "/app/OrderController.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for @RequestParam -> kafkaTemplate.send()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_TaskQueue_SpringKafkaTemplateSendDefault(t *testing.T) {
	code := `
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class EventPublisher {
    private final KafkaTemplate<String, String> kafkaTemplate;

    public EventPublisher(KafkaTemplate<String, String> kafkaTemplate) {
        this.kafkaTemplate = kafkaTemplate;
    }

    @PostMapping("/events")
    public void publish(@RequestParam String event) {
        kafkaTemplate.sendDefault(event);
    }
}
`
	flows := Analyze(code, "/app/EventPublisher.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for @RequestParam -> kafkaTemplate.sendDefault()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_TaskQueue_SpringRabbitTemplateConvertAndSend(t *testing.T) {
	code := `
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class NotificationController {
    private final RabbitTemplate rabbitTemplate;

    public NotificationController(RabbitTemplate rabbitTemplate) {
        this.rabbitTemplate = rabbitTemplate;
    }

    @PostMapping("/notify")
    public void notify(@RequestParam String message) {
        rabbitTemplate.convertAndSend("notifications.exchange", "user.notify", message);
    }
}
`
	flows := Analyze(code, "/app/NotificationController.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for @RequestParam -> rabbitTemplate.convertAndSend()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_TaskQueue_SpringJmsTemplateConvertAndSend(t *testing.T) {
	code := `
import org.springframework.jms.core.JmsTemplate;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuditController {
    private final JmsTemplate jmsTemplate;

    public AuditController(JmsTemplate jmsTemplate) {
        this.jmsTemplate = jmsTemplate;
    }

    @PostMapping("/audit")
    public void audit(@RequestBody String auditPayload) {
        jmsTemplate.convertAndSend("audit.queue", auditPayload);
    }
}
`
	flows := Analyze(code, "/app/AuditController.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for @RequestBody -> jmsTemplate.convertAndSend()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_TaskQueue_RabbitMQChannelBasicPublish(t *testing.T) {
	code := `
import com.rabbitmq.client.Channel;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PublisherController {
    private final Channel channel;

    public PublisherController(Channel channel) {
        this.channel = channel;
    }

    @PostMapping("/publish")
    public void publish(@RequestParam String body) throws Exception {
        channel.basicPublish("tasks.exchange", "tasks.run", null, body.getBytes());
    }
}
`
	flows := Analyze(code, "/app/PublisherController.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for @RequestParam -> channel.basicPublish()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_TaskQueue_SpringStreamBridgeSend(t *testing.T) {
	code := `
import org.springframework.cloud.stream.function.StreamBridge;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AnalyticsController {
    private final StreamBridge streamBridge;

    public AnalyticsController(StreamBridge streamBridge) {
        this.streamBridge = streamBridge;
    }

    @PostMapping("/analytics")
    public void emit(@RequestParam String event) {
        streamBridge.send("analytics-out-0", event);
    }
}
`
	flows := Analyze(code, "/app/AnalyticsController.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for @RequestParam -> streamBridge.send()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Safe fixture: constant payload must NOT produce a trust-boundary flow ---

func TestJava_TaskQueue_SpringKafkaTemplateSend_Safe(t *testing.T) {
	code := `
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HeartbeatController {
    private final KafkaTemplate<String, String> kafkaTemplate;

    public HeartbeatController(KafkaTemplate<String, String> kafkaTemplate) {
        this.kafkaTemplate = kafkaTemplate;
    }

    @PostMapping("/heartbeat")
    public void beat() {
        kafkaTemplate.send("heartbeat", "alive");
    }
}
`
	flows := Analyze(code, "/app/HeartbeatController.java", rules.LangJava)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary {
			t.Errorf("did not expect trust-boundary flow for constant payload; got %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
