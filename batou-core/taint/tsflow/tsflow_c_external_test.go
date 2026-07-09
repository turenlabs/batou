package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// C external source tests (SrcExternal)
// =========================================================================

func TestC_RdKafkaConsumerPoll_ToCommand(t *testing.T) {
	code := `
#include <librdkafka/rdkafka.h>
#include <stdlib.h>

void process_kafka(rd_kafka_t *rk) {
    rd_kafka_message_t *msg = rd_kafka_consumer_poll(rk, 1000);
    system((const char *)msg->payload);
}
`
	flows := Analyze(code, "/app/kafka_handler.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for rd_kafka_consumer_poll -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_RdKafkaConsume_ToSQLQuery(t *testing.T) {
	code := `
#include <librdkafka/rdkafka.h>
#include <sqlite3.h>

void ingest_kafka(rd_kafka_topic_t *topic, sqlite3 *db) {
    rd_kafka_message_t *msg = rd_kafka_consume(topic, 0, 1000);
    const char *payload = (const char *)msg->payload;
    sqlite3_exec(db, payload, NULL, NULL, NULL);
}
`
	flows := Analyze(code, "/app/kafka_ingest.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for rd_kafka_consume -> sqlite3_exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_HiredisCommand_ToCommand(t *testing.T) {
	code := `
#include <hiredis/hiredis.h>
#include <stdlib.h>

void exec_cached(redisContext *c, const char *key) {
    redisReply *reply = redisCommand(c, "GET %s", key);
    system(reply->str);
}
`
	flows := Analyze(code, "/app/redis_exec.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for redisCommand -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_HiredisCommandArgv_ToFileWrite(t *testing.T) {
	code := `
#include <hiredis/hiredis.h>
#include <stdio.h>

void dump_redis(redisContext *c) {
    const char *argv[] = {"GET", "cached_data"};
    size_t argvlen[] = {3, 11};
    redisReply *reply = redisCommandArgv(c, 2, argv, argvlen);
    FILE *f = fopen("/tmp/dump.txt", "w");
    fputs(reply->str, f);
}
`
	flows := Analyze(code, "/app/redis_dump.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file write flow for redisCommandArgv -> fputs")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_AmqpBasicGet_ToCommand(t *testing.T) {
	code := `
#include <amqp.h>
#include <stdlib.h>

void process_rabbitmq(amqp_connection_state_t conn) {
    amqp_rpc_reply_t reply = amqp_basic_get(conn, 1, amqp_cstring_bytes("tasks"), 1);
    system((const char *)reply.reply_type);
}
`
	flows := Analyze(code, "/app/rabbitmq_worker.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for amqp_basic_get -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_AmqpConsumeMessage_ToCommand(t *testing.T) {
	code := `
#include <amqp.h>
#include <stdlib.h>

void consume_rabbitmq(amqp_connection_state_t conn) {
    amqp_rpc_reply_t reply = amqp_consume_message(conn, NULL, NULL, 0);
    system((const char *)reply.reply_type);
}
`
	flows := Analyze(code, "/app/rabbitmq_consume.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for amqp_consume_message -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_ZmqRecv_ToCommand(t *testing.T) {
	code := `
#include <zmq.h>
#include <stdlib.h>

void handle_zmq(void *socket) {
    char *buf = zmq_recv(socket, NULL, 0, 0);
    system(buf);
}
`
	flows := Analyze(code, "/app/zmq_handler.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for zmq_recv -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_ZmqMsgRecv_ToCommand(t *testing.T) {
	code := `
#include <zmq.h>
#include <stdlib.h>

void save_zmq_msg(void *socket) {
    zmq_msg_t msg;
    zmq_msg_init(&msg);
    char *data = zmq_msg_recv(&msg, socket, 0);
    system(data);
}
`
	flows := Analyze(code, "/app/zmq_save.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for zmq_msg_recv -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_MQTTClientReceive_ToCommand(t *testing.T) {
	code := `
#include <MQTTClient.h>
#include <stdlib.h>

void handle_mqtt(MQTTClient client) {
    MQTTClient_message *msg = MQTTClient_receive(client, NULL, NULL, NULL, 5000);
    system((const char *)msg->payload);
}
`
	flows := Analyze(code, "/app/mqtt_handler.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for MQTTClient_receive -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_SdBusMessageRead_ToCommand(t *testing.T) {
	code := `
#include <systemd/sd-bus.h>
#include <stdlib.h>

void handle_dbus(sd_bus_message *m) {
    const char *data = sd_bus_message_read(m, "s");
    system(data);
}
`
	flows := Analyze(code, "/app/dbus_handler.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for sd_bus_message_read -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_NngRecv_ToCommand(t *testing.T) {
	code := `
#include <nng/nng.h>
#include <stdlib.h>

void handle_nng(nng_socket sock) {
    char *buf = nng_recv(sock, NULL, 0, 0);
    system(buf);
}
`
	flows := Analyze(code, "/app/nng_handler.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for nng_recv -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_NatsNextMsg_ToCommand(t *testing.T) {
	code := `
#include <nats/nats.h>
#include <stdlib.h>

void handle_nats(natsSubscription *sub) {
    natsMsg *msg = natsSubscription_NextMsg(sub, 5000);
    system(msg->data);
}
`
	flows := Analyze(code, "/app/nats_handler.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for natsSubscription_NextMsg -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_MemcachedGet_ToCommand(t *testing.T) {
	code := `
#include <libmemcached/memcached.h>
#include <stdlib.h>

void exec_cached(memcached_st *memc, const char *key) {
    size_t val_len;
    uint32_t flags;
    memcached_return_t rc;
    char *val = memcached_get(memc, key, strlen(key), &val_len, &flags, &rc);
    system(val);
}
`
	flows := Analyze(code, "/app/memcached_exec.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for memcached_get -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Negative test — safe usage should NOT produce external source flows
// =========================================================================

func TestC_RedisCommand_SafeUsage_NoFlow(t *testing.T) {
	code := `
#include <hiredis/hiredis.h>
#include <stdio.h>
#include <string.h>

void safe_redis(redisContext *c) {
    redisReply *reply = redisCommand(c, "PING");
    if (strcmp(reply->str, "PONG") == 0) {
        printf("Redis is up\n");
    }
    freeReplyObject(reply);
}
`
	flows := Analyze(code, "/app/redis_health.c", rules.LangC)
	for _, f := range flows {
		if f.Source.Category == taint.SrcExternal && f.Sink.Category == taint.SnkCommand {
			t.Error("unexpected command injection flow for safe Redis PING usage")
		}
	}
}
