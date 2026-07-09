package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Python — Task queue trust boundary: Celery / RQ / Dramatiq / arq (CWE-501)
// =========================================================================
//
// Producer side: a web handler pushes user-controlled values into a task
// queue. The args are serialized (pickle/JSON) into the broker (Redis /
// RabbitMQ / SQS) and later deserialized + re-executed by a worker in a
// privileged context. Tainted arg → cross-boundary re-execution.
//
// These mirror the existing Ruby Sidekiq / Resque / ActiveJob trust
// boundary sinks; Python had the consumer-side source (py.celery.task_args)
// but no producer-side sink until now.

func TestPython_TaskQueue_CeleryApplyAsync(t *testing.T) {
	code := `
from flask import request
from tasks import send_email

def handler():
    recipient = request.args.get("to")
    send_email.apply_async(args=[recipient])
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for request.args -> send_email.apply_async()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_TaskQueue_CelerySendTask(t *testing.T) {
	code := `
from flask import request
from myapp import app

def handler():
    payload = request.args.get("payload")
    app.send_task("tasks.process", args=[payload])
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for request.args -> app.send_task()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_TaskQueue_RQEnqueue(t *testing.T) {
	code := `
from flask import request
from rq import Queue
from redis import Redis
from tasks import do_work

q = Queue(connection=Redis())

def handler():
    data = request.args.get("data")
    q.enqueue(do_work, data)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for request.args -> q.enqueue()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_TaskQueue_RQEnqueueIn(t *testing.T) {
	code := `
from flask import request
from datetime import timedelta
from rq import Queue
from redis import Redis
from tasks import reminder

q = Queue(connection=Redis())

def handler():
    msg = request.args.get("msg")
    q.enqueue_in(timedelta(hours=1), reminder, msg)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for request.args -> q.enqueue_in()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_TaskQueue_RQEnqueueAt(t *testing.T) {
	code := `
from flask import request
from datetime import datetime
from rq import Queue
from redis import Redis
from tasks import reminder

q = Queue(connection=Redis())

def handler():
    note = request.args.get("note")
    q.enqueue_at(datetime(2030, 1, 1), reminder, note)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for request.args -> q.enqueue_at()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_TaskQueue_DramatiqSendWithOptions(t *testing.T) {
	code := `
from flask import request
from tasks import notify

def handler():
    body = request.args.get("body")
    notify.send_with_options(args=(body,), delay=5000)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for request.args -> actor.send_with_options()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_TaskQueue_ArqEnqueueJob(t *testing.T) {
	code := `
from flask import request
from arq import create_pool

async def handler():
    name = request.args.get("name")
    redis = await create_pool()
    await redis.enqueue_job("greet", name)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for request.args -> redis.enqueue_job()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Safe: coercing to int before enqueue removes the trust boundary risk ---

func TestPython_TaskQueue_RQEnqueue_Sanitized_IntCoercion(t *testing.T) {
	code := `
from flask import request
from rq import Queue
from redis import Redis
from tasks import process_user

q = Queue(connection=Redis())

def handler():
    user_id = int(request.args.get("user_id"))
    q.enqueue(process_user, user_id)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected NO trust boundary flow — int() should coerce to integer")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
