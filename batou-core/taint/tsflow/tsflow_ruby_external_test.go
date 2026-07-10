package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Ruby — SrcExternal sources: message queues, caches, job processors
// =========================================================================

// --- Bunny (RabbitMQ) ---

func TestRuby_Source_BunnyBasicGet_CommandInjection(t *testing.T) {
	code := `
require "bunny"

def process_message(channel, queue_name)
  payload = channel.basic_get(queue_name)
  system(payload)
end
`
	flows := Analyze(code, "/app/consumer.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from Bunny basic_get payload")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRuby_Source_BunnyBasicConsume_CommandInjection(t *testing.T) {
	code := `
require "bunny"

def start_consumer(channel)
  tag = channel.basic_consume("tasks")
  system(tag)
end
`
	flows := Analyze(code, "/app/worker.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from Bunny basic_consume")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Dalli (Memcached) ---

func TestRuby_Source_DalliGet_CommandInjection(t *testing.T) {
	code := `
require "dalli"

def lookup_user
  dalli = Dalli::Client.new
  cached_cmd = dalli.get("user_cmd")
  system(cached_cmd)
end
`
	flows := Analyze(code, "/app/cache.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from Dalli.get")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRuby_Source_DalliGetMulti_CommandInjection(t *testing.T) {
	code := `
require "dalli"

def run_cached_commands(dalli)
  results = dalli.get_multi("cmd1", "cmd2")
  system(results["cmd1"])
end
`
	flows := Analyze(code, "/app/batch.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from Dalli.get_multi")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Kafka ---

func TestRuby_Source_KafkaEachMessage_CommandInjection(t *testing.T) {
	code := `
require "kafka"

def consume_events(consumer)
  msg = consumer.each_message {}
  system(msg)
end
`
	flows := Analyze(code, "/app/kafka_consumer.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from Kafka each_message")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- NATS ---

func TestRuby_Source_NatsSubscribe_CommandInjection(t *testing.T) {
	code := `
require "nats/client"

def listen(nats)
  data = nats.subscribe("tasks")
  system(data)
end
`
	flows := Analyze(code, "/app/nats_listener.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from NATS subscribe")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Redis additional operations ---

func TestRuby_Source_RedisHget_CommandInjection(t *testing.T) {
	code := `
require "redis"

def lookup(redis)
  name = redis.hget("users", "admin_name")
  system(name)
end
`
	flows := Analyze(code, "/app/redis_lookup.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from Redis hget")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRuby_Source_RedisHgetall_CommandInjection(t *testing.T) {
	code := `
require "redis"

def run_tasks(redis)
  tasks = redis.hgetall("pending_tasks")
  system(tasks["first"])
end
`
	flows := Analyze(code, "/app/redis_tasks.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from Redis hgetall")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRuby_Source_RedisLpop_CommandInjection(t *testing.T) {
	code := `
require "redis"

def process_queue(redis)
  item = redis.lpop("work_queue")
  system(item)
end
`
	flows := Analyze(code, "/app/redis_queue.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from Redis lpop")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRuby_Source_RedisSmembers_CommandInjection(t *testing.T) {
	code := `
require "redis"

def run_set_commands(redis)
  members = redis.smembers("commands")
  system(members.first)
end
`
	flows := Analyze(code, "/app/redis_set.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from Redis smembers")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRuby_Source_RedisMget_CommandInjection(t *testing.T) {
	code := `
require "redis"

def batch_lookup(redis)
  values = redis.mget("key1", "key2")
  system(values.first)
end
`
	flows := Analyze(code, "/app/redis_batch.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from Redis mget")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Safe patterns (sanitized) ---

func TestRuby_Source_DalliGet_Sanitized_NoFlow(t *testing.T) {
	code := `
require "dalli"

def safe_lookup
  dalli = Dalli::Client.new
  cached = dalli.get("user_id")
  id = cached.to_i
  puts id
end
`
	flows := Analyze(code, "/app/safe_cache.rb", rules.LangRuby)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand {
			t.Error("expected no command injection flow when Dalli value is sanitized via to_i")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
