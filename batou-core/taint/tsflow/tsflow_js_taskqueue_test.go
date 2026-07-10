package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// ===========================================================================
// JavaScript — task-queue producer trust-boundary sinks (CWE-501)
// ===========================================================================
// When a web handler pushes user-controlled values into a background job queue
// (Bull/BullMQ, bee-queue, node-resque, amqplib), the payload is serialized to
// Redis/AMQP and re-executed later in a worker context. Worker code that
// assumes internal/trusted payloads is open to secondary injection and logic
// bypass. Mirror of the Python py.rq.enqueue / py.celery.apply_async and
// Ruby Sidekiq/Resque/ActiveJob trust-boundary sinks.

func TestJS_BullMQ_AddBulk_TaintedPayload(t *testing.T) {
	code := `
const { Queue } = require('bullmq');
const queue = new Queue('emails');

async function handler(req, res) {
    const body = req.body;
    await queue.addBulk([
        { name: 'welcome', data: body },
        { name: 'audit', data: body },
    ]);
    res.send('queued');
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected SnkTrustBoundary flow for req.body -> BullMQ queue.addBulk")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_BeeQueue_CreateJob_TaintedPayload(t *testing.T) {
	code := `
const Queue = require('bee-queue');
const addQueue = new Queue('addition');

function handler(req, res) {
    const body = req.body;
    const job = addQueue.createJob(body);
    job.save();
    res.send('ok');
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected SnkTrustBoundary flow for req.body -> bee-queue createJob")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_NodeResque_Enqueue_TaintedArgs(t *testing.T) {
	code := `
const { Queue } = require('node-resque');
const queue = new Queue({ connection: {} });

async function handler(req, res) {
    const userId = req.params.id;
    await queue.enqueue('math', 'add', [userId, 10]);
    res.send('queued');
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected SnkTrustBoundary flow for req.params.id -> node-resque enqueue args")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_NodeResque_EnqueueIn_TaintedArgs(t *testing.T) {
	code := `
const { Queue } = require('node-resque');
const queue = new Queue({ connection: {} });

async function handler(req, res) {
    const payload = req.body.task;
    await queue.enqueueIn(60000, 'math', 'add', [payload]);
    res.send('scheduled');
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected SnkTrustBoundary flow for req.body.task -> node-resque enqueueIn args")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_NodeResque_EnqueueAt_TaintedArgs(t *testing.T) {
	code := `
const { Queue } = require('node-resque');
const queue = new Queue({ connection: {} });

async function handler(req, res) {
    const userPayload = req.body.payload;
    await queue.enqueueAt(1735689600000, 'math', 'add', [userPayload]);
    res.send('scheduled');
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected SnkTrustBoundary flow for req.body.payload -> node-resque enqueueAt args")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_Amqplib_SendToQueue_TaintedBuffer(t *testing.T) {
	code := `
const amqp = require('amqplib');

async function handler(req, res) {
    const conn = await amqp.connect('amqp://localhost');
    const channel = await conn.createChannel();
    const body = req.body;
    channel.sendToQueue('tasks', Buffer.from(JSON.stringify(body)));
    res.send('published');
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected SnkTrustBoundary flow for req.body -> amqplib channel.sendToQueue")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Safe path: constant payloads (no user input) must NOT produce a taint flow.
func TestJS_TaskQueue_ConstantPayload_NoFlow(t *testing.T) {
	code := `
const { Queue } = require('bullmq');
const queue = new Queue('emails');

async function scheduled() {
    await queue.addBulk([
        { name: 'warmup', data: { kind: 'internal' } },
    ]);
}
`
	flows := Analyze(code, "/app/scheduled.js", rules.LangJavaScript)
	if hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected NO SnkTrustBoundary flow for constant payload into addBulk")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
