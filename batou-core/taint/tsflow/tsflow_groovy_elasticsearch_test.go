package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Groovy Elasticsearch / OpenSearch query-DSL + Painless injection tests
// (CWE-943 / CWE-94). Mirrors the Java ES coverage (PR #436): Groovy on the
// JVM imports the same client classes (QueryBuilders, Request, Elasticsearch
// Java API Client 8.x, Spring Data Elasticsearch). Direct parameter -> sink
// flows are exercised; pure parameter+string-concat is a known Groovy tsflow
// gap and is not covered here.
// =========================================================================

// --- QueryBuilders.wrapperQuery: raw JSON query DSL ---

func TestGroovy_Elasticsearch_WrapperQuery_Injection(t *testing.T) {
	code := `
def handler(filter) {
    def q = QueryBuilders.wrapperQuery(filter)
    return q
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !findSinkIDES(flows, "groovy.elasticsearch.querybuilders.wrapperquery") {
		t.Error("expected groovy.elasticsearch.querybuilders.wrapperquery finding for parameter -> QueryBuilders.wrapperQuery")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s src=%s", f.Sink.ID, f.Sink.Category, f.Source.Category)
		}
	}
}

// --- QueryBuilders.queryStringQuery: Lucene operator injection ---

func TestGroovy_Elasticsearch_QueryStringQuery_Injection(t *testing.T) {
	code := `
def handler(term) {
    def q = QueryBuilders.queryStringQuery(term)
    return q
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !findSinkIDES(flows, "groovy.elasticsearch.querybuilders.querystringquery") {
		t.Error("expected groovy.elasticsearch.querybuilders.querystringquery finding")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s src=%s", f.Sink.ID, f.Sink.Category, f.Source.Category)
		}
	}
}

// --- QueryBuilders.simpleQueryStringQuery: simplified Lucene injection ---

func TestGroovy_Elasticsearch_SimpleQueryStringQuery_Injection(t *testing.T) {
	code := `
def handler(term) {
    def q = QueryBuilders.simpleQueryStringQuery(term)
    return q
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !findSinkIDES(flows, "groovy.elasticsearch.querybuilders.simplequerystringquery") {
		t.Error("expected groovy.elasticsearch.querybuilders.simplequerystringquery finding")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s src=%s", f.Sink.ID, f.Sink.Category, f.Source.Category)
		}
	}
}

// --- QueryBuilders.scriptQuery with tainted Painless source: RCE on ES cluster ---

func TestGroovy_Elasticsearch_ScriptQuery_PainlessRCE(t *testing.T) {
	code := `
def handler(source) {
    def q = QueryBuilders.scriptQuery(source)
    return q
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected Painless-RCE flow for parameter -> QueryBuilders.scriptQuery")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s src=%s", f.Sink.ID, f.Sink.Category, f.Source.Category)
		}
	}
}

// --- Low-level REST client: Request.setJsonEntity(raw JSON) ---

func TestGroovy_Elasticsearch_Request_SetJsonEntity_Injection(t *testing.T) {
	code := `
def handler(body) {
    def esReq = new Request("POST", "/logs/_search")
    esReq.setJsonEntity(body)
    restClient.performRequest(esReq)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !findSinkIDES(flows, "groovy.elasticsearch.request.setjsonentity") {
		t.Error("expected groovy.elasticsearch.request.setjsonentity finding for parameter -> setJsonEntity")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s src=%s", f.Sink.ID, f.Sink.Category, f.Source.Category)
		}
	}
}

// --- ES Java API Client 8.x: client.updateByQuery (Painless + DSL body) ---

func TestGroovy_Elasticsearch_UpdateByQuery_Injection(t *testing.T) {
	code := `
def handler(script) {
    client.updateByQuery(script)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected Painless-RCE flow for parameter -> client.updateByQuery")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s src=%s", f.Sink.ID, f.Sink.Category, f.Source.Category)
		}
	}
}

// --- ES Java API Client 8.x: client.deleteByQuery (DSL injection) ---

func TestGroovy_Elasticsearch_DeleteByQuery_Injection(t *testing.T) {
	code := `
def handler(query) {
    client.deleteByQuery(query)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !findSinkIDES(flows, "groovy.elasticsearch.client.deletebyquery") {
		t.Error("expected groovy.elasticsearch.client.deletebyquery finding")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s src=%s", f.Sink.ID, f.Sink.Category, f.Source.Category)
		}
	}
}

// --- ES Java API Client 8.x: client.msearch (NDJSON body) ---

func TestGroovy_Elasticsearch_Msearch_Injection(t *testing.T) {
	code := `
def handler(body) {
    client.msearch(body)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !findSinkIDES(flows, "groovy.elasticsearch.client.msearch") {
		t.Error("expected groovy.elasticsearch.client.msearch finding")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s src=%s", f.Sink.ID, f.Sink.Category, f.Source.Category)
		}
	}
}

// --- ES Java API Client 8.x: client.scriptsPainlessExecute (direct RCE) ---
// Note: a parameter literally named "script" is filtered by the Groovy
// source-name heuristic, so we use "body" — the realistic API takes a
// PainlessExecuteRequest whose source field is the tainted Painless string.

func TestGroovy_Elasticsearch_ScriptsPainlessExecute_RCE(t *testing.T) {
	code := `
def handler(body) {
    client.scriptsPainlessExecute(body)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected Painless-RCE flow for parameter -> client.scriptsPainlessExecute")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s src=%s", f.Sink.ID, f.Sink.Category, f.Source.Category)
		}
	}
}

// --- ES Java API Client 8.x: client.putScript (persistent Painless) ---

func TestGroovy_Elasticsearch_PutScript_Persistent_RCE(t *testing.T) {
	code := `
def handler(body) {
    client.putScript(body)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected Painless-RCE flow for parameter -> client.putScript")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s src=%s", f.Sink.ID, f.Sink.Category, f.Source.Category)
		}
	}
}

// --- ES SearchTemplate: Mustache template injection ---

func TestGroovy_Elasticsearch_SearchTemplate_Injection(t *testing.T) {
	code := `
def handler(body) {
    client.searchTemplate(body)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !findSinkIDES(flows, "groovy.elasticsearch.client.searchtemplate") {
		t.Error("expected groovy.elasticsearch.client.searchtemplate finding")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s src=%s", f.Sink.ID, f.Sink.Category, f.Source.Category)
		}
	}
}

// --- Spring Data Elasticsearch: new StringQuery(rawJson) ---

func TestGroovy_Elasticsearch_Spring_StringQuery_Injection(t *testing.T) {
	code := `
def handler(json) {
    def q = new StringQuery(json)
    ops.search(q, Object.class)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !findSinkIDES(flows, "groovy.spring.elasticsearch.stringquery.new") {
		t.Error("expected groovy.spring.elasticsearch.stringquery.new finding")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s src=%s", f.Sink.ID, f.Sink.Category, f.Source.Category)
		}
	}
}

// =========================================================================
// Negative tests: hardcoded queries should NOT produce ES sink findings
// =========================================================================

// Hardcoded wrapperQuery (no source taint) — should produce no flow.

func TestGroovy_Elasticsearch_WrapperQuery_Hardcoded_NoFlow(t *testing.T) {
	code := `
def run() {
    def q = QueryBuilders.wrapperQuery('{"match_all":{}}')
    return q
}
`
	flows := Analyze(code, "/app/run.groovy", rules.LangGroovy)
	for _, f := range flows {
		if f.Sink.ID == "groovy.elasticsearch.querybuilders.wrapperquery" {
			t.Errorf("expected NO flow for hardcoded wrapperQuery literal, got src=%s", f.Source.Category)
		}
	}
}

// Hardcoded msearch (no source taint) — should produce no flow.

func TestGroovy_Elasticsearch_Msearch_Hardcoded_NoFlow(t *testing.T) {
	code := `
def run() {
    client.msearch('{"index":"a"}\n{"query":{"match_all":{}}}\n')
}
`
	flows := Analyze(code, "/app/run.groovy", rules.LangGroovy)
	for _, f := range flows {
		if f.Sink.ID == "groovy.elasticsearch.client.msearch" {
			t.Errorf("expected NO flow for hardcoded msearch body, got src=%s", f.Source.Category)
		}
	}
}

// findSinkIDES is a local helper to avoid colliding with findSinkID in
// other groovy_*_test.go files within the tsflow package.
func findSinkIDES(flows []taint.TaintFlow, id string) bool {
	for _, f := range flows {
		if f.Sink.ID == id {
			return true
		}
	}
	return false
}
