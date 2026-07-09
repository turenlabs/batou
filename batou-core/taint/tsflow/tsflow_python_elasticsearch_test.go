package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Python elasticsearch-py NoSQL/DSL injection + Painless RCE tests
// (CWE-943 / CWE-94 / CWE-89). Only ES-specific method names are covered
// here — generic method names like search/update/count live in the regex
// layer (BATOU-NOSQL-*) to avoid stdlib/pandas false positives.
// =========================================================================

func TestPython_Elasticsearch_MSearchBody(t *testing.T) {
	code := `
from flask import request
from elasticsearch import Elasticsearch

es = Elasticsearch()

def multi_search():
    term = request.args.get("term")
    body = [
        {"index": "logs"},
        {"query": {"match": {"message": term}}},
    ]
    return es.msearch(body=body)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected DSL injection flow for request.args.get -> es.msearch")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_Elasticsearch_DeleteByQuery(t *testing.T) {
	code := `
from flask import request
from elasticsearch import Elasticsearch

es = Elasticsearch()

def purge():
    tag = request.form.get("tag")
    return es.delete_by_query(index="items", body={
        "query": {"match": {"tag": tag}}
    })
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected DSL injection flow for request.form.get -> es.delete_by_query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_Elasticsearch_UpdateByQueryScript(t *testing.T) {
	code := `
from flask import request
from elasticsearch import Elasticsearch

es = Elasticsearch()

def bulk_update():
    src = request.json["script_source"]
    return es.update_by_query(index="items", body={
        "script": {"source": src, "lang": "painless"},
        "query": {"match_all": {}},
    })
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected Painless RCE flow for request.json -> es.update_by_query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_Elasticsearch_ScriptsPainlessExecute(t *testing.T) {
	code := `
from flask import request
from elasticsearch import Elasticsearch

es = Elasticsearch()

def run_script():
    src = request.json["source"]
    return es.scripts_painless_execute(body={
        "script": {"source": src, "lang": "painless"}
    })
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected direct Painless RCE flow for request.json -> es.scripts_painless_execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_Elasticsearch_PutScriptStored(t *testing.T) {
	code := `
from flask import request
from elasticsearch import Elasticsearch

es = Elasticsearch()

def save_script():
    src = request.form.get("src")
    return es.put_script(id="calc", body={
        "script": {"source": src, "lang": "painless"}
    })
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected stored-script RCE flow for request.form.get -> es.put_script")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_Elasticsearch_SQLQuery(t *testing.T) {
	code := `
from flask import request
from elasticsearch import Elasticsearch

es = Elasticsearch()

def sql_query():
    q = request.args.get("q")
    return es.sql.query(body={"query": q})
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for request.args.get -> es.sql.query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_Elasticsearch_TransportPerformRequest(t *testing.T) {
	code := `
from flask import request
from elasticsearch import Elasticsearch

es = Elasticsearch()

def raw_api():
    path = request.args.get("path")
    return es.transport.perform_request("GET", path, body=None)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected raw-transport injection flow for request.args.get -> es.transport.perform_request")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_Elasticsearch_AsyncDeleteByQuery(t *testing.T) {
	code := `
from fastapi import FastAPI, Request
from elasticsearch import AsyncElasticsearch

app = FastAPI()
es = AsyncElasticsearch()

@app.get("/purge")
async def purge(request: Request):
    tag = request.query_params.get("tag")
    return await es.delete_by_query(index="logs", body={
        "query": {"match": {"tag": tag}}
    })
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected async DSL injection flow for request.query_params.get -> es.delete_by_query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Negative tests: safe usage should NOT produce elasticsearch sink findings ---

func TestPython_Elasticsearch_Safe_HardcodedScriptSource(t *testing.T) {
	code := `
from elasticsearch import Elasticsearch

es = Elasticsearch()

def bump():
    return es.update_by_query(index="items", body={
        "script": {"source": "ctx._source.count++", "lang": "painless"},
        "query": {"match_all": {}},
    })
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.ID == "py.elasticsearch.update_by_query" {
			t.Errorf("unexpected update_by_query sink firing on hardcoded script: %s", f.Sink.ID)
		}
	}
}
