package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
)

// Tests for C++ SrcExternal sources: Kafka, RabbitMQ, ZeroMQ, MQTT, D-Bus, nng, NATS.
// Each test verifies that data from an external messaging/IPC source
// flows to a dangerous sink (command injection or path traversal).
//
// The tsflow walker traces taint through return-value assignments.
// All tests use: result = source_func(...) → result->field → sink().

func TestCPP_Kafka_ConsumerPoll_CommandInjection(t *testing.T) {
	code := `
#include <librdkafka/rdkafka.h>
#include <cstdlib>

void process(rd_kafka_t *rk) {
    rd_kafka_message_t *msg = rd_kafka_consumer_poll(rk, 1000);
    char *data = msg->payload;
    system(data);
}
`
	flows := Analyze(code, "/app/kafka_consumer.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow: rd_kafka_consumer_poll -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Kafka_LegacyConsume_FileWrite(t *testing.T) {
	code := `
#include <librdkafka/rdkafka.h>
#include <cstdio>

void process(rd_kafka_topic_t *topic) {
    rd_kafka_message_t *msg = rd_kafka_consume(topic, 0, 1000);
    char *path = msg->payload;
    fopen(path, "w");
}
`
	flows := Analyze(code, "/app/kafka_worker.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected path traversal flow: rd_kafka_consume -> fopen")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_RabbitMQ_BasicGet_CommandInjection(t *testing.T) {
	code := `
#include <amqp.h>
#include <cstdlib>

void fetch(amqp_connection_state_t conn) {
    amqp_rpc_reply_t reply = amqp_basic_get(conn, 1, amqp_cstring_bytes("tasks"), 1);
    char *body = reply.library_error;
    system(body);
}
`
	flows := Analyze(code, "/app/rabbitmq_get.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow: amqp_basic_get -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_RabbitMQ_ConsumeMessage_CommandInjection(t *testing.T) {
	code := `
#include <amqp.h>
#include <cstdlib>

void consume(amqp_connection_state_t conn) {
    amqp_envelope_t *envelope = amqp_consume_message(conn, NULL, NULL, 0);
    char *cmd = envelope->message;
    system(cmd);
}
`
	flows := Analyze(code, "/app/rabbitmq_consumer.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow: amqp_consume_message -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_ZeroMQ_Recv_CommandInjection(t *testing.T) {
	code := `
#include <zmq.h>
#include <cstdlib>

void handle(void *socket) {
    char *buffer = zmq_recv(socket, NULL, 0, 0);
    system(buffer);
}
`
	flows := Analyze(code, "/app/zmq_handler.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow: zmq_recv -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_ZeroMQ_MsgRecv_FileWrite(t *testing.T) {
	code := `
#include <zmq.h>
#include <cstdio>

void execute(void *socket) {
    zmq_msg_t *msg = zmq_msg_recv(NULL, socket, 0);
    char *path = msg->data;
    fopen(path, "r");
}
`
	flows := Analyze(code, "/app/zmq_worker.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected path traversal flow: zmq_msg_recv -> fopen")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_MQTT_ClientReceive_CommandInjection(t *testing.T) {
	code := `
#include <MQTTClient.h>
#include <cstdlib>

void process(MQTTClient client) {
    MQTTClient_message *msg = MQTTClient_receive(client, NULL, NULL, NULL, 5000);
    char *payload = msg->payload;
    system(payload);
}
`
	flows := Analyze(code, "/app/mqtt_handler.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow: MQTTClient_receive -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_DBus_MessageRead_CommandInjection(t *testing.T) {
	code := `
#include <systemd/sd-bus.h>
#include <cstdlib>

int method_handler(sd_bus_message *m) {
    const char *command = sd_bus_message_read(m, "s", NULL);
    system(command);
    return 0;
}
`
	flows := Analyze(code, "/app/dbus_service.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow: sd_bus_message_read -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Nng_Recv_FileWrite(t *testing.T) {
	code := `
#include <nng/nng.h>
#include <cstdio>

void handle(nng_socket sock) {
    char *buf = nng_recv(sock, NULL, NULL, 0);
    fopen(buf, "r");
}
`
	flows := Analyze(code, "/app/nng_handler.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected path traversal flow: nng_recv -> fopen")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_NATS_SubscriptionNextMsg_CommandInjection(t *testing.T) {
	code := `
#include <nats/nats.h>
#include <cstdlib>

void process(natsSubscription *sub) {
    natsMsg *msg = natsSubscription_NextMsg(NULL, sub, 5000);
    const char *data = msg->data;
    system(data);
}
`
	flows := Analyze(code, "/app/nats_worker.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow: natsSubscription_NextMsg -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
