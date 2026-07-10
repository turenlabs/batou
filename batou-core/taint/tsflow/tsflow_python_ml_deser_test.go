package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Python ML/distributed-computing deserialization sinks — CWE-502
//
// These libraries all wrap or extend pickle and inherit its full RCE
// semantics when loading attacker-controlled byte streams.
// =========================================================================

func TestPython_MLDeserSinks_Registered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangPython)
	if cat == nil {
		t.Fatal("Python catalog not loaded")
	}
	sinks := cat.Sinks()
	found := map[string]bool{}
	for _, s := range sinks {
		if s.Category == taint.SnkDeserialize {
			found[s.ID] = true
		}
	}
	want := []string{
		"py.dill.loads",
		"py.dill.load",
		"py.cloudpickle.loads",
		"py.cloudpickle.load",
		"py.jsonpickle.decode",
		"py.joblib.load",
		"py.xmlrpc.client.loads",
		"py.torch.load",
	}
	for _, id := range want {
		if !found[id] {
			t.Errorf("missing expected SnkDeserialize sink: %s", id)
		}
	}
}

// --- dill ---

func TestPython_DillLoads_RCE(t *testing.T) {
	code := `
import dill

def handler():
    data = request.files["payload"].read()
    obj = dill.loads(data)
    return str(obj)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow from request.files -> dill.loads()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_DillLoad_RCE(t *testing.T) {
	code := `
import dill

def handler():
    uploaded = request.files["artifact"]
    obj = dill.load(uploaded)
    return str(obj)
`
	flows := Analyze(code, "/app/artifacts.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow from request.files -> dill.load()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- cloudpickle ---

func TestPython_CloudpickleLoads_RCE(t *testing.T) {
	code := `
import cloudpickle

def worker_handler():
    payload = request.data
    fn = cloudpickle.loads(payload)
    return fn()
`
	flows := Analyze(code, "/app/worker.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow from request.data -> cloudpickle.loads()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_CloudpickleLoad_RCE(t *testing.T) {
	code := `
import cloudpickle

def handler():
    upload = request.files["task"]
    obj = cloudpickle.load(upload)
    return str(obj)
`
	flows := Analyze(code, "/app/dask_task.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow from request.files -> cloudpickle.load()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- jsonpickle ---

func TestPython_JsonpickleDecode_RCE(t *testing.T) {
	code := `
import jsonpickle

def handler():
    raw = request.json.get("state")
    obj = jsonpickle.decode(raw)
    return str(obj)
`
	flows := Analyze(code, "/app/session.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow from request.json -> jsonpickle.decode() (CVE-2020-22083)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- joblib ---

func TestPython_JoblibLoad_RCE(t *testing.T) {
	code := `
import joblib

def predict():
    model_path = request.args.get("model")
    model = joblib.load(model_path)
    return model.predict([[1, 2, 3]])
`
	flows := Analyze(code, "/app/ml_api.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow from request.args -> joblib.load()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- xmlrpc.client ---

func TestPython_XmlrpcClientLoads_RCE(t *testing.T) {
	code := `
import xmlrpc.client

def handler():
    payload = request.data
    params, method = xmlrpc.client.loads(payload)
    return str(params)
`
	flows := Analyze(code, "/app/rpc.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow from request.data -> xmlrpc.client.loads()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- torch.load ---

func TestPython_TorchLoad_RCE(t *testing.T) {
	code := `
import torch

def load_checkpoint():
    ckpt_path = request.args.get("ckpt")
    state = torch.load(ckpt_path)
    return str(state)
`
	flows := Analyze(code, "/app/inference.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow from request.args -> torch.load() (HuggingFace/torch-hub supply-chain vector)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
