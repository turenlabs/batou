package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Python extended sources — Falcon, Bottle, Pyramid, Kafka, RabbitMQ,
// gRPC, httpx, WebSocket, asyncpg, tortoise-orm, pickle, protobuf
// =========================================================================

func TestPython_ExtSourcesRegistered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangPython)
	if cat == nil {
		t.Fatal("Python catalog not loaded")
	}
	sources := cat.Sources()
	ids := map[string]bool{}
	for _, s := range sources {
		ids[s.ID] = true
	}
	want := []string{
		"py.falcon.req.get_param",
		"py.falcon.req.bounded_stream",
		"py.falcon.req.media",
		"py.falcon.req.get_header",
		"py.bottle.request.forms",
		"py.bottle.request.params",
		"py.pyramid.request.params",
		"py.kafka.consumer.poll",
		"py.kafka.msg.value",
		"py.pika.basic_consume",
		"py.grpc.request",
		"py.httpx.response",
		"py.websocket.receive",
		"py.asyncpg.fetch",
		"py.tortoise.model.all",
		"py.pickle.loads",
		"py.protobuf.parse",
		"py.protobuf.fromstring",
	}
	for _, id := range want {
		if !ids[id] {
			t.Errorf("missing expected source: %s", id)
		}
	}
}

// --- Falcon ---

func TestPython_Falcon_GetParam_SQLi(t *testing.T) {
	code := `
import falcon
import sqlite3

class ItemResource:
    def on_get(self, req, resp):
        name = req.get_param("name")
        conn = sqlite3.connect("app.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM items WHERE name = '" + name + "'")
        resp.media = cursor.fetchall()
`
	flows := Analyze(code, "/app/resources.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from req.get_param() -> cursor.execute()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_Falcon_Media_CommandInj(t *testing.T) {
	code := `
import falcon
import os

class DeployResource:
    def on_post(self, req, resp):
        data = req.media
        os.system("deploy " + data["target"])
`
	flows := Analyze(code, "/app/resources.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from req.media -> os.system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_Falcon_GetHeader_XSS(t *testing.T) {
	code := `
import falcon
from starlette.responses import HTMLResponse

class InfoResource:
    def on_get(self, req, resp):
        ua = req.get_header("User-Agent")
        return HTMLResponse("<html><body>Your browser: " + ua + "</body></html>")
`
	flows := Analyze(code, "/app/resources.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow from req.get_header() -> HTMLResponse()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Bottle ---

func TestPython_Bottle_Forms_SQLi(t *testing.T) {
	code := `
from bottle import request
import sqlite3

def login():
    username = request.forms.get("username")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from request.forms.get() -> cursor.execute()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_Bottle_Params_CommandInj(t *testing.T) {
	code := `
from bottle import request
import os

def run_tool():
    tool = request.params.get("tool")
    os.system("run_" + tool)
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from request.params.get() -> os.system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Pyramid ---

func TestPython_Pyramid_Params_SQLi(t *testing.T) {
	code := `
import sqlite3

def my_view(request):
    name = request.params.get("name")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from Pyramid request.params.get() -> cursor.execute()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Kafka ---

func TestPython_Kafka_ConsumerPoll_SQLi(t *testing.T) {
	code := `
from confluent_kafka import Consumer
import sqlite3

def process_messages():
    consumer = Consumer(conf)
    msg = consumer.poll(1.0)
    data = msg.value()
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO events VALUES ('" + data.decode() + "')")
`
	flows := Analyze(code, "/app/consumer.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from consumer.poll() / msg.value() -> cursor.execute()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- RabbitMQ (pika) ---

func TestPython_Pika_BasicConsume_CommandInj(t *testing.T) {
	code := `
import pika
import os

def callback(ch, method, properties, body):
    os.system("process " + body.decode())

connection = pika.BlockingConnection()
channel = connection.channel()
channel.basic_consume(queue="tasks", on_message_callback=callback)
`
	flows := Analyze(code, "/app/worker.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from basic_consume callback body -> os.system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- gRPC (regex-only — tsflow can't trace function-def source patterns) ---

func TestPython_gRPC_SourceRegistered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangPython)
	if cat == nil {
		t.Fatal("Python catalog not loaded")
	}
	for _, src := range cat.Sources() {
		if src.ID == "py.grpc.request" {
			if src.Category != taint.SrcExternal {
				t.Errorf("py.grpc.request should be SrcExternal, got %s", src.Category)
			}
			return
		}
	}
	t.Error("py.grpc.request source not found in catalog")
}

// --- httpx ---

func TestPython_Httpx_Response_Eval(t *testing.T) {
	code := `
import httpx

def fetch_config(url):
    data = httpx.get(url)
    config = eval(data)
`
	flows := Analyze(code, "/app/config.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval injection flow from httpx.get() -> eval()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- WebSocket (no await — Python await unwrapping not yet in tsflow) ---

func TestPython_WebSocket_Receive_SQLi(t *testing.T) {
	code := `
import sqlite3

def ws_handler(websocket):
    data = websocket.receive_text()
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM messages WHERE content = '" + data + "'")
`
	flows := Analyze(code, "/app/ws.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from websocket.receive_text() -> cursor.execute()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- asyncpg (no await — Python await unwrapping not yet in tsflow) ---

func TestPython_Asyncpg_Fetch_CommandInj(t *testing.T) {
	code := `
import os

def process_commands(conn):
    rows = conn.fetch("SELECT cmd FROM jobs WHERE status = 'pending'")
    for row in rows:
        os.system(row["cmd"])
`
	flows := Analyze(code, "/app/jobs.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from asyncpg conn.fetch() -> os.system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- tortoise-orm (regex-only — tsflow can't match arbitrary model class receivers) ---

func TestPython_TortoiseORM_SourceRegistered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangPython)
	if cat == nil {
		t.Fatal("Python catalog not loaded")
	}
	for _, src := range cat.Sources() {
		if src.ID == "py.tortoise.model.all" {
			if src.Category != taint.SrcDatabase {
				t.Errorf("py.tortoise.model.all should be SrcDatabase, got %s", src.Category)
			}
			return
		}
	}
	t.Error("py.tortoise.model.all source not found in catalog")
}

// --- pickle ---

func TestPython_Pickle_Loads_Eval(t *testing.T) {
	code := `
import pickle

def load_config(data):
    config = pickle.loads(data)
    eval(config["expr"])
`
	flows := Analyze(code, "/app/config.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval injection flow from pickle.loads() -> eval()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- protobuf ---

func TestPython_Protobuf_FromString_SQLi(t *testing.T) {
	code := `
import sqlite3
from myproto import user_pb2

def handle_message(raw_bytes):
    msg = user_pb2.UserRequest.FromString(raw_bytes)
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + msg.name + "'")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from protobuf FromString() -> cursor.execute()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Negative tests (safe patterns) ---

func TestPython_Falcon_SafeParam_NoFlow(t *testing.T) {
	code := `
import falcon
import sqlite3

class ItemResource:
    def on_get(self, req, resp):
        name = req.get_param("name")
        conn = sqlite3.connect("app.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM items WHERE name = ?", (name,))
        resp.media = cursor.fetchall()
`
	flows := Analyze(code, "/app/resources.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("parameterized query should NOT produce SQL injection flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
