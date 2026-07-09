package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"

	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Lua / OpenResty — Message broker / task queue producer trust-boundary sinks (CWE-501)
//
// When an OpenResty service publishes user-controlled values into one of
// these brokers (lua-resty-kafka, lua-resty-rabbitmqstomp, lua-resty-redis
// pub/sub), the payload crosses the process boundary and is later
// deserialized + re-processed by a consumer running in a privileged
// context — a CWE-501 trust-boundary violation.
// =========================================================================

func TestLua_RestyKafka_ProducerSend_TrustBoundary(t *testing.T) {
	code := `
local producer = require "resty.kafka.producer"
function handler()
    local args = ngx.req.get_uri_args()
    local payload = args["payload"]
    local p = producer:new(broker_list, { producer_type = "async" })
    local ok, err = p:send("events", "key1", payload)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for ngx.req.get_uri_args -> p:send")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_RestyKafka_ProducerSend_NamedReceiver_TrustBoundary(t *testing.T) {
	code := `
local producer_lib = require "resty.kafka.producer"
function handler()
    local body = ngx.req.get_body_data()
    local producer = producer_lib:new(broker_list)
    producer:send("audit-log", nil, body)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for ngx.req.get_body_data -> producer:send")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_RestyRabbitMQStomp_Send_TrustBoundary(t *testing.T) {
	code := `
local rabbitmq = require "resty.rabbitmqstomp"
function handler()
    local headers_in = ngx.req.get_headers()
    local msg = headers_in["X-Payload"]
    local rabbit = rabbitmq:new()
    rabbit:set_timeout(10000)
    rabbit:connect("127.0.0.1", 61613)
    local headers = { destination = "/exchange/test/binding" }
    rabbit:send(msg, headers)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for ngx.req.get_headers -> rabbit:send")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_RestyRedis_Publish_TrustBoundary(t *testing.T) {
	code := `
local redis = require "resty.redis"
function handler()
    local args = ngx.req.get_uri_args()
    local message = args["message"]
    local red = redis:new()
    red:connect("127.0.0.1", 6379)
    red:publish("notifications", message)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for ngx.req.get_uri_args -> red:publish")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative test: hardcoded payloads must NOT produce a trust-boundary flow.
func TestLua_RestyKafka_HardcodedPayload_NoFlow(t *testing.T) {
	code := `
local producer = require "resty.kafka.producer"
function handler()
    local p = producer:new(broker_list)
    p:send("heartbeat", "key", "ping")
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary {
			t.Errorf("did NOT expect trust-boundary flow for hardcoded payload, got: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
