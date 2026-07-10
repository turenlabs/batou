package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// C message-broker producer tests (SnkTrustBoundary / CWE-501)
//
// These mirror the C++ broker tests in tsflow_cpp_taskqueue_test.go but
// exercise the C-flavored API surface (bare getenv from <stdlib.h>, no
// std:: prefix, C-style headers). They cover the C-side gap where the
// CONSUMER sources (c.rdkafka.consume, c.nats.subscription_nextmsg,
// c.zmq.recv, c.nng.recv, c.amqp.basic_get, c.mqtt.client_receive) were
// already in the catalog but the matching PRODUCER sinks were missing.
// =========================================================================

func TestC_RdKafkaProduce_TrustBoundary(t *testing.T) {
	code := `
#include <librdkafka/rdkafka.h>
#include <stdlib.h>
#include <string.h>

void publish(rd_kafka_topic_t *rkt) {
    char *payload = getenv("USER_BODY");
    rd_kafka_produce(rkt, RD_KAFKA_PARTITION_UA, RD_KAFKA_MSG_F_COPY,
                     payload, strlen(payload), NULL, 0, NULL);
}
`
	flows := Analyze(code, "/app/kafka_produce.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for getenv -> rd_kafka_produce")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestC_RdKafkaProducev_TrustBoundary(t *testing.T) {
	code := `
#include <librdkafka/rdkafka.h>
#include <stdlib.h>
#include <string.h>

void publish_v(rd_kafka_t *rk, rd_kafka_topic_t *rkt) {
    char *body = getenv("MSG");
    rd_kafka_producev(rk,
        RD_KAFKA_V_RKT(rkt),
        RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),
        RD_KAFKA_V_VALUE(body, strlen(body)),
        RD_KAFKA_V_END);
}
`
	flows := Analyze(code, "/app/kafka_producev.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for getenv -> rd_kafka_producev")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestC_MosquittoPublish_TrustBoundary(t *testing.T) {
	code := `
#include <mosquitto.h>
#include <stdlib.h>
#include <string.h>

void publish_telemetry(struct mosquitto *mosq) {
    char *payload = getenv("TELEMETRY_BODY");
    mosquitto_publish(mosq, NULL, "sensors/room1", strlen(payload), payload, 1, false);
}
`
	flows := Analyze(code, "/app/mqtt_publish.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for getenv -> mosquitto_publish")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestC_MosquittoPublishV5_TrustBoundary(t *testing.T) {
	code := `
#include <mosquitto.h>
#include <stdlib.h>
#include <string.h>

void publish_v5(struct mosquitto *mosq, mosquitto_property *props) {
    char *payload = getenv("MQTT_V5_BODY");
    mosquitto_publish_v5(mosq, NULL, "topic/v5", strlen(payload), payload, 1, false, props);
}
`
	flows := Analyze(code, "/app/mqtt_publish_v5.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for getenv -> mosquitto_publish_v5")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestC_PahoMqttPublish_TrustBoundary(t *testing.T) {
	code := `
#include <MQTTClient.h>
#include <stdlib.h>
#include <string.h>

void send_event(MQTTClient client, MQTTClient_deliveryToken *dt) {
    char *payload = getenv("PAHO_BODY");
    MQTTClient_publish(client, "events/user", (int)strlen(payload), payload, 1, 0, dt);
}
`
	flows := Analyze(code, "/app/paho_publish.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for getenv -> MQTTClient_publish")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestC_NatsPublish_TrustBoundary(t *testing.T) {
	code := `
#include <nats/nats.h>
#include <stdlib.h>
#include <string.h>

void send_event(natsConnection *nc) {
    char *data = getenv("EVENT_PAYLOAD");
    natsConnection_Publish(nc, "events.user", data, (int)strlen(data));
}
`
	flows := Analyze(code, "/app/nats_publish.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for getenv -> natsConnection_Publish")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestC_NatsPublishString_TrustBoundary(t *testing.T) {
	code := `
#include <nats/nats.h>
#include <stdlib.h>

void send_str(natsConnection *nc) {
    char *str = getenv("LOG_LINE");
    natsConnection_PublishString(nc, "logs.app", str);
}
`
	flows := Analyze(code, "/app/nats_publish_string.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for getenv -> natsConnection_PublishString")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestC_NatsPublishRequest_TrustBoundary(t *testing.T) {
	code := `
#include <nats/nats.h>
#include <stdlib.h>
#include <string.h>

void rpc_send(natsConnection *nc) {
    char *data = getenv("RPC_BODY");
    natsConnection_PublishRequest(nc, "rpc.echo", "_INBOX.42", data, (int)strlen(data));
}
`
	flows := Analyze(code, "/app/nats_publish_request.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for getenv -> natsConnection_PublishRequest")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestC_NatsPublishRequestString_TrustBoundary(t *testing.T) {
	code := `
#include <nats/nats.h>
#include <stdlib.h>

void rpc_send_str(natsConnection *nc) {
    char *str = getenv("RPC_STR");
    natsConnection_PublishRequestString(nc, "rpc.echo", "_INBOX.43", str);
}
`
	flows := Analyze(code, "/app/nats_publish_request_string.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for getenv -> natsConnection_PublishRequestString")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestC_RabbitMQCBasicPublish_TrustBoundary(t *testing.T) {
	code := `
#include <amqp.h>
#include <stdlib.h>

void publish_amqp(amqp_connection_state_t state) {
    char *body_str = getenv("AMQP_BODY");
    amqp_basic_publish(state, 1, amqp_cstring_bytes("ex"), amqp_cstring_bytes("rk"),
                       0, 0, NULL, amqp_cstring_bytes(body_str));
}
`
	flows := Analyze(code, "/app/rabbitmq_publish.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for getenv -> amqp_basic_publish")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestC_ZmqSend_TrustBoundary(t *testing.T) {
	code := `
#include <zmq.h>
#include <stdlib.h>
#include <string.h>

void send_zmq(void *socket) {
    char *buf = getenv("ZMQ_BODY");
    zmq_send(socket, buf, strlen(buf), 0);
}
`
	flows := Analyze(code, "/app/zmq_send.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for getenv -> zmq_send")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestC_NngSend_TrustBoundary(t *testing.T) {
	code := `
#include <nng/nng.h>
#include <stdlib.h>
#include <string.h>

void send_nng(nng_socket sock) {
    char *data = getenv("NNG_PAYLOAD");
    nng_send(sock, data, strlen(data), 0);
}
`
	flows := Analyze(code, "/app/nng_send.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for getenv -> nng_send")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

// =========================================================================
// Negative regression tests — constant payloads should NOT produce flows.
// Guards against future changes that might over-broaden the matchers.
// =========================================================================

func TestC_RdKafkaProduce_ConstantPayload_NoFlow(t *testing.T) {
	code := `
#include <librdkafka/rdkafka.h>
#include <string.h>

void heartbeat(rd_kafka_topic_t *rkt) {
    const char *payload = "ping";
    rd_kafka_produce(rkt, RD_KAFKA_PARTITION_UA, RD_KAFKA_MSG_F_COPY,
                     (void*)payload, strlen(payload), NULL, 0, NULL);
}
`
	flows := Analyze(code, "/app/kafka_heartbeat.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("constant payload to rd_kafka_produce should NOT produce a trust-boundary flow")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestC_NatsPublish_ConstantPayload_NoFlow(t *testing.T) {
	code := `
#include <nats/nats.h>
#include <string.h>

void send_static(natsConnection *nc) {
    const char *data = "{\"event\":\"startup\"}";
    natsConnection_Publish(nc, "events.system", (void*)data, (int)strlen(data));
}
`
	flows := Analyze(code, "/app/nats_static.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("constant payload to natsConnection_Publish should NOT produce a trust-boundary flow")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}
