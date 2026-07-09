package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Python SrcDeserialized sources — deserialized data flowing to other sinks
// =========================================================================

func TestPython_DeserSources_Registered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangPython)
	if cat == nil {
		t.Fatal("Python catalog not loaded")
	}
	sources := cat.Sources()
	found := map[string]bool{}
	for _, s := range sources {
		if s.Category == taint.SrcDeserialized {
			found[s.ID] = true
		}
	}
	want := []string{
		"py.json.loads",
		"py.yaml.safe_load",
		"py.yaml.safe_load_all",
		"py.toml.loads",
		"py.toml.load",
		"py.xmltodict.parse",
		"py.msgpack.unpackb",
		"py.orjson.loads",
		"py.ujson.loads",
	}
	for _, id := range want {
		if !found[id] {
			t.Errorf("missing expected SrcDeserialized source: %s", id)
		}
	}
}

// --- YAML safe_load ---

func TestPython_YamlSafeLoad_SQLi(t *testing.T) {
	code := `
import yaml

def load_config():
    with open("config.yaml") as f:
        config = yaml.safe_load(f)
    cursor.execute("SELECT * FROM " + config["table"])
`
	flows := Analyze(code, "/app/loader.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from yaml.safe_load() -> cursor.execute()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_YamlSafeLoadAll_CommandInjection(t *testing.T) {
	code := `
import yaml
import os

def run_tasks():
    with open("tasks.yaml") as f:
        docs = yaml.safe_load_all(f)
    for doc in docs:
        os.system(doc["command"])
`
	flows := Analyze(code, "/app/runner.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from yaml.safe_load_all() -> os.system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- TOML ---

func TestPython_TomlLoads_SQLi(t *testing.T) {
	code := `
import toml

def load_settings(raw):
    settings = toml.loads(raw)
    cursor.execute("SELECT * FROM " + settings["table_name"])
`
	flows := Analyze(code, "/app/settings.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from toml.loads() -> cursor.execute()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_TomlibLoad_CommandInjection(t *testing.T) {
	code := `
import tomllib

def apply_config():
    with open("deploy.toml", "rb") as f:
        cfg = tomllib.load(f)
    os.system(cfg["deploy_cmd"])
`
	flows := Analyze(code, "/app/deploy.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from tomllib.load() -> os.system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- xmltodict ---

func TestPython_XmltodictParse_SQLi(t *testing.T) {
	code := `
import xmltodict

def import_xml(xml_data):
    doc = xmltodict.parse(xml_data)
    cursor.execute("INSERT INTO items VALUES ('" + doc["item"]["name"] + "')")
`
	flows := Analyze(code, "/app/importer.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from xmltodict.parse() -> cursor.execute()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- msgpack ---

func TestPython_MsgpackUnpackb_CommandInjection(t *testing.T) {
	code := `
import msgpack
import subprocess

def handle_message(raw_bytes):
    msg = msgpack.unpackb(raw_bytes)
    subprocess.call(msg["cmd"], shell=True)
`
	flows := Analyze(code, "/app/worker.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from msgpack.unpackb() -> subprocess.call()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- orjson ---

func TestPython_OrjsonLoads_SQLi(t *testing.T) {
	code := `
import orjson

def process_payload(raw):
    data = orjson.loads(raw)
    cursor.execute("SELECT * FROM users WHERE name = '" + data["name"] + "'")
`
	flows := Analyze(code, "/app/api.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from orjson.loads() -> cursor.execute()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- ujson ---

func TestPython_UjsonLoads_Eval(t *testing.T) {
	code := `
import ujson

def run_dynamic(payload_str):
    payload = ujson.loads(payload_str)
    result = eval(payload["expression"])
`
	flows := Analyze(code, "/app/dynamic.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval injection flow from ujson.loads() -> eval()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Safe pattern: deserialized data with validation ---

func TestPython_YamlSafeLoad_Sanitized_IntCast(t *testing.T) {
	code := `
import yaml

def load_config():
    with open("config.yaml") as f:
        config = yaml.safe_load(f)
    page = int(config["page"])
    cursor.execute("SELECT * FROM items LIMIT " + str(page))
`
	flows := Analyze(code, "/app/loader.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Error("expected NO SQL injection flow when int() sanitizes the deserialized value")
		}
	}
}
