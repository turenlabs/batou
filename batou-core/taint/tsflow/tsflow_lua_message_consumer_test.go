package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"

	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Lua / OpenResty — Message broker CONSUMER trust-boundary sources (CWE-501)
//
// Symmetric to the producer trust-boundary sinks exercised in
// tsflow_lua_taskqueue_test.go. When an OpenResty service consumes records
// from a Kafka topic or a RabbitMQ STOMP subscription, the message body was
// last touched by an outside process. Treating it as trusted input on the
// receiving side is a CWE-501 trust-boundary violation; values must be
// validated/sanitized before reaching SQL, command, eval, or HTML output.
// =========================================================================

func TestLua_RestyKafka_ConsumerFetch_AsCommandSource(t *testing.T) {
	code := `
local kafka_consumer = require "resty.kafka.consumer"
function handler()
    local consumer = kafka_consumer:new(broker_list, "events", 0)
    local result = consumer:fetch("events", 0, 0)
    os.execute(result)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for consumer:fetch -> os.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestLua_RestyKafka_ConsumerFetch_AsXSSSource(t *testing.T) {
	code := `
local kafka_consumer = require "resty.kafka.consumer"
function handler()
    local consumer = kafka_consumer:new(broker_list, "audit-log", 0)
    local payload = consumer:fetch("audit-log", 0, 0)
    ngx.say(payload)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for consumer:fetch -> ngx.say")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestLua_RestyKafka_ConsumerFetch_ShortReceiver(t *testing.T) {
	code := `
local kafka_consumer = require "resty.kafka.consumer"
function handler()
    local c = kafka_consumer:new(broker_list, "topic1", 0)
    local data = c:fetch("topic1", 0, 0)
    os.execute(data)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for c:fetch -> os.execute (short receiver)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestLua_RestyRabbitMQStomp_Receive_AsSQLSource(t *testing.T) {
	code := `
local rabbitmq = require "resty.rabbitmqstomp"
function handler()
    local rabbit = rabbitmq:new()
    rabbit:set_timeout(10000)
    rabbit:connect("127.0.0.1", 61613)
    rabbit:subscribe({ destination = "/queue/jobs" })
    local body = rabbit:receive()
    local pg = require "pgmoon"
    pg:query("SELECT * FROM jobs WHERE name = '" .. body .. "'")
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL-injection flow for rabbit:receive -> pg:query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestLua_RestyRabbitMQStomp_Receive_AsXSSSource(t *testing.T) {
	code := `
local rabbitmq = require "resty.rabbitmqstomp"
function handler()
    local rabbit = rabbitmq:new()
    rabbit:connect("127.0.0.1", 61613)
    rabbit:subscribe({ destination = "/queue/notifications" })
    local body = rabbit:receive()
    ngx.print(body)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for rabbit:receive -> ngx.print")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

// Negative test: a constant string passed to a downstream sink must NOT be
// reported as flowing from the consumer source.
func TestLua_ConsumerSources_NoFlow_Constant(t *testing.T) {
	code := `
function handler()
    os.execute("echo hello")
    ngx.say("static body")
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Source.ID == "lua.resty.kafka.consumer.fetch" || f.Source.ID == "lua.resty.rabbitmqstomp.receive" {
			t.Errorf("did NOT expect consumer source flow for constant payload, got: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}
