package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// ===========================================================================
// JavaScript/TypeScript — Cloudflare Workers bindings
//
// Adds first-class coverage for the four canonical Workers data bindings:
//   D1Database  — env.DB.exec(sql)         CWE-89  SnkSQLQuery
//   Queue       — env.QUEUE.send / sendBatch CWE-501 SnkTrustBoundary
//   KVNamespace — env.KV.get / getWithMetadata (second-order taint source)
//   R2Bucket    — env.R2.get                 (second-order taint source)
//
// Mirrors the redis-py (PR #685), Jedis (PR #641), and go-redis (PR #647)
// second-order source patterns plus the amqplib / bullmq queue trust-boundary
// pattern. End-to-end flows are verified by wiring the new sources to an
// existing eval / fetch / html sink so the SnkEval / SnkURLFetch / SnkHTMLOutput
// finding fires from the new source ID.
// ===========================================================================

// flowFromSourceTo reports whether any flow originates from the given source
// ID and terminates at any sink of the given category. Used to assert
// second-order-taint reads (KV/R2) reach a downstream injection sink.
func flowFromSourceTo(flows []taint.TaintFlow, srcID string, snkCat taint.SinkCategory) bool {
	for _, f := range flows {
		if f.Source.ID == srcID && f.Sink.Category == snkCat {
			return true
		}
	}
	return false
}

// --- D1Database SQL injection sink ---

func TestJS_Cloudflare_D1_Exec_SQLInjection(t *testing.T) {
	code := `
async function handler(request, env) {
    const name = request.headers.get('x-user');
    await env.DB.exec("UPDATE users SET name = '" + name + "' WHERE id = 1");
}
`
	flows := Analyze(code, "/app/workers/d1.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SnkSQLQuery flow: request.headers -> env.DB.exec")
		for _, f := range flows {
			t.Logf("  flow: %s (%s) -> %s (%s) conf=%.2f",
				f.Source.ID, f.Source.Category, f.Sink.ID, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_Cloudflare_D1_Exec_SQLInjection_TemplateLiteral(t *testing.T) {
	code := `
async function handler(request, env) {
    const id = request.headers.get('x-user-id');
    await env.DB.exec(` + "`SELECT * FROM events WHERE user_id='${id}'`" + `);
}
`
	flows := Analyze(code, "/app/workers/d1tpl.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SnkSQLQuery flow via template literal: headers -> env.DB.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// Negative: a constant SQL string passed to env.DB.exec must NOT produce a
// SnkSQLQuery flow — there is no tainted source reaching the sink.
func TestJS_Cloudflare_D1_Exec_ConstantSQL_NoFlow(t *testing.T) {
	code := `
async function migrate(env) {
    await env.DB.exec("CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY)");
}
`
	flows := Analyze(code, "/app/workers/migrate.js", rules.LangJavaScript)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("constant SQL must NOT trigger a SnkSQLQuery flow")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// --- Queue trust-boundary sinks ---

func TestJS_Cloudflare_Queue_Send_TrustBoundary(t *testing.T) {
	code := `
async function handler(request, env) {
    const body = await request.json();
    await env.QUEUE.send(body);
}
`
	flows := Analyze(code, "/app/workers/queue.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected SnkTrustBoundary flow: request.json -> env.QUEUE.send")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestJS_Cloudflare_Queue_SendBatch_TrustBoundary(t *testing.T) {
	code := `
async function handler(request, env) {
    const data = await request.json();
    await env.QUEUE.sendBatch([{ body: data }]);
}
`
	flows := Analyze(code, "/app/workers/queuebatch.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected SnkTrustBoundary flow: request.json -> env.QUEUE.sendBatch")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// Negative: a static / hard-coded queue message must NOT trigger SnkTrustBoundary.
func TestJS_Cloudflare_Queue_Send_StaticPayload_NoFlow(t *testing.T) {
	code := `
async function ping(env) {
    await env.QUEUE.send({ kind: "heartbeat", ts: Date.now() });
}
`
	flows := Analyze(code, "/app/workers/ping.js", rules.LangJavaScript)
	if hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("static queue payload must NOT trigger a SnkTrustBoundary flow")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// --- KVNamespace second-order-taint sources ---
//
// Pattern: attacker writes data via KV.put on one request; a later request
// reads it via KV.get and feeds the value into a downstream sink (eval here).
// Without js.cloudflare.kv.get, the eval call would see only an
// unannotated value and miss the second-order flow.

func TestJS_Cloudflare_KV_Get_ToEval(t *testing.T) {
	code := `
async function replay(request, env) {
    const script = await env.KV.get('replay:script');
    eval(script);
}
`
	flows := Analyze(code, "/app/workers/replay.js", rules.LangJavaScript)
	if !flowFromSourceTo(flows, "js.cloudflare.kv.get", taint.SnkEval) {
		t.Error("expected js.cloudflare.kv.get -> SnkEval second-order flow")
		for _, f := range flows {
			t.Logf("  flow: %s (%s) -> %s (%s)", f.Source.ID, f.Source.Category, f.Sink.ID, f.Sink.Category)
		}
	}
}

func TestJS_Cloudflare_KV_GetWithMetadata_ToEval(t *testing.T) {
	code := `
async function run(request, env) {
    const result = await env.KV.getWithMetadata('replay:script');
    eval(result.value);
}
`
	flows := Analyze(code, "/app/workers/runner.js", rules.LangJavaScript)
	if !flowFromSourceTo(flows, "js.cloudflare.kv.getwithmetadata", taint.SnkEval) {
		t.Error("expected js.cloudflare.kv.getwithmetadata -> SnkEval second-order flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// --- R2Bucket second-order-taint source ---

func TestJS_Cloudflare_R2_Get_ToEval(t *testing.T) {
	code := `
async function replay(request, env) {
    const obj = await env.R2.get('artifacts/payload.js');
    const body = await obj.text();
    eval(body);
}
`
	flows := Analyze(code, "/app/workers/r2eval.js", rules.LangJavaScript)
	if !flowFromSourceTo(flows, "js.cloudflare.r2.get", taint.SnkEval) {
		t.Error("expected js.cloudflare.r2.get -> SnkEval second-order flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}
