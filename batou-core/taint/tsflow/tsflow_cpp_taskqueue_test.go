package tsflow

import (
	"testing"

	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// C++ message-broker / task-queue producer trust-boundary tests (CWE-501)
// librdkafka, cnats, rabbitmq-c, Paho MQTT C, libmosquitto, libzmq.
// Tainted web/env input is published into a broker and later deserialized
// + processed by a consumer in a privileged context.
// =========================================================================

func TestCPP_RdKafkaProduce_TrustBoundary(t *testing.T) {
	code := `
#include <librdkafka/rdkafka.h>
#include <cstdlib>
#include <cstring>

void publish(rd_kafka_topic_t *rkt) {
    char *payload = std::getenv("USER_BODY");
    rd_kafka_produce(rkt, RD_KAFKA_PARTITION_UA, RD_KAFKA_MSG_F_COPY,
                     payload, std::strlen(payload), NULL, 0, NULL);
}
`
	flows := Analyze(code, "/app/kafka_produce.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for getenv -> rd_kafka_produce")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_RdKafkaProducev_TrustBoundary(t *testing.T) {
	code := `
#include <librdkafka/rdkafka.h>
#include <cstdlib>
#include <cstring>

void publish_v(rd_kafka_t *rk, rd_kafka_topic_t *rkt) {
    char *body = std::getenv("MSG");
    rd_kafka_producev(rk,
        RD_KAFKA_V_RKT(rkt),
        RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),
        RD_KAFKA_V_VALUE(body, std::strlen(body)),
        RD_KAFKA_V_END);
}
`
	flows := Analyze(code, "/app/kafka_producev.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for getenv -> rd_kafka_producev")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_NatsPublish_TrustBoundary(t *testing.T) {
	code := `
#include <nats/nats.h>
#include <cstdlib>
#include <cstring>

void send_event(natsConnection *nc) {
    char *data = std::getenv("EVENT_PAYLOAD");
    natsConnection_Publish(nc, "events.user", data, (int)std::strlen(data));
}
`
	flows := Analyze(code, "/app/nats_publish.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for getenv -> natsConnection_Publish")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_NatsPublishString_TrustBoundary(t *testing.T) {
	code := `
#include <nats/nats.h>
#include <cstdlib>

void send_string(natsConnection *nc) {
    char *s = std::getenv("RAW_CMD");
    natsConnection_PublishString(nc, "jobs.queue", s);
}
`
	flows := Analyze(code, "/app/nats_publishstring.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for getenv -> natsConnection_PublishString")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_NatsPublishRequest_TrustBoundary(t *testing.T) {
	code := `
#include <nats/nats.h>
#include <cstdlib>
#include <cstring>

void request(natsConnection *nc) {
    char *body = std::getenv("REQ_BODY");
    natsConnection_PublishRequest(nc, "svc.rpc", "reply.inbox",
                                  body, (int)std::strlen(body));
}
`
	flows := Analyze(code, "/app/nats_publishrequest.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for getenv -> natsConnection_PublishRequest")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_NatsPublishRequestString_TrustBoundary(t *testing.T) {
	code := `
#include <nats/nats.h>
#include <cstdlib>

void request_str(natsConnection *nc) {
    char *s = std::getenv("REQ_STR");
    natsConnection_PublishRequestString(nc, "svc.rpc", "reply.inbox", s);
}
`
	flows := Analyze(code, "/app/nats_publishrequeststring.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for getenv -> natsConnection_PublishRequestString")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_RabbitMQCBasicPublish_TrustBoundary(t *testing.T) {
	code := `
#include <amqp.h>
#include <cstdlib>
#include <cstring>

void publish_amqp(amqp_connection_state_t conn) {
    char *body = std::getenv("AMQP_BODY");
    amqp_basic_publish(conn, 1,
                       amqp_cstring_bytes("exchange"),
                       amqp_cstring_bytes("routing.key"),
                       0, 0, NULL,
                       amqp_cstring_bytes(body));
}
`
	flows := Analyze(code, "/app/amqp_publish.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for getenv -> amqp_basic_publish")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_MQTTClientPublish_TrustBoundary(t *testing.T) {
	code := `
#include <MQTTClient.h>
#include <cstdlib>
#include <cstring>

void publish_mqtt(MQTTClient client) {
    char *payload = std::getenv("MQTT_BODY");
    MQTTClient_deliveryToken token;
    MQTTClient_publish(client, "sensors/temp",
                       (int)std::strlen(payload), payload,
                       1, 0, &token);
}
`
	flows := Analyze(code, "/app/mqtt_publish.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for getenv -> MQTTClient_publish")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_MQTTAsyncSend_TrustBoundary(t *testing.T) {
	code := `
#include <MQTTAsync.h>
#include <cstdlib>
#include <cstring>

void publish_async(MQTTAsync client) {
    char *payload = std::getenv("MQTT_BODY");
    MQTTAsync_responseOptions opts = MQTTAsync_responseOptions_initializer;
    MQTTAsync_send(client, "topic/a",
                   (int)std::strlen(payload), payload,
                   1, 0, &opts);
}
`
	flows := Analyze(code, "/app/mqtt_async_send.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for getenv -> MQTTAsync_send")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_MosquittoPublish_TrustBoundary(t *testing.T) {
	code := `
#include <mosquitto.h>
#include <cstdlib>
#include <cstring>

void publish_mosq(struct mosquitto *mosq) {
    char *payload = std::getenv("MOSQ_BODY");
    mosquitto_publish(mosq, NULL, "home/sensor",
                      (int)std::strlen(payload), payload, 1, false);
}
`
	flows := Analyze(code, "/app/mosquitto_publish.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for getenv -> mosquitto_publish")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_ZmqSend_TrustBoundary(t *testing.T) {
	code := `
#include <zmq.h>
#include <cstdlib>
#include <cstring>

void send_zmq(void *socket) {
    char *buf = std::getenv("ZMQ_BUF");
    zmq_send(socket, buf, std::strlen(buf), 0);
}
`
	flows := Analyze(code, "/app/zmq_send.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for getenv -> zmq_send")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_ZmqSendConst_TrustBoundary(t *testing.T) {
	code := `
#include <zmq.h>
#include <cstdlib>
#include <cstring>

void send_const_zmq(void *socket) {
    char *buf = std::getenv("ZMQ_BUF");
    zmq_send_const(socket, buf, std::strlen(buf), 0);
}
`
	flows := Analyze(code, "/app/zmq_send_const.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for getenv -> zmq_send_const")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_ZmqMsgSend_TrustBoundary(t *testing.T) {
	// zmq_msg_send's 0th arg is an already-built message. The common
	// vulnerable shape is a caller passing a tainted pointer straight in.
	code := `
#include <zmq.h>
#include <cstdlib>

void forward(void *socket) {
    char *tainted = std::getenv("ZMQ_MSG");
    zmq_msg_send((zmq_msg_t *)tainted, socket, 0);
}
`
	flows := Analyze(code, "/app/zmq_msg_send.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for tainted buffer -> zmq_msg_send")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Safe: hardcoded payload — no taint source should reach the producer sink.
func TestCPP_RdKafkaProduce_HardcodedPayload_NoFlow(t *testing.T) {
	code := `
#include <librdkafka/rdkafka.h>

void publish_static(rd_kafka_topic_t *rkt) {
    const char *payload = "{\"event\":\"ping\"}";
    rd_kafka_produce(rkt, RD_KAFKA_PARTITION_UA, RD_KAFKA_MSG_F_COPY,
                     (void*)payload, 16, NULL, 0, NULL);
}
`
	flows := Analyze(code, "/app/kafka_static.cpp", rules.LangCPP)
	if hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("unexpected trust-boundary flow for hardcoded payload -> rd_kafka_produce")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
