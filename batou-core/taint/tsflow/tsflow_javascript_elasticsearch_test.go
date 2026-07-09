package tsflow

import (
	"testing"

	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// JavaScript/TypeScript Elasticsearch (and OpenSearch) NoSQL/DSL injection +
// Painless RCE tests (CWE-943 / CWE-94).
//
// @elastic/elasticsearch and @opensearch-project/opensearch share identical
// camelCase method names on Client. A single sink set covers both. Methods
// that accept a 'script' field (updateByQuery / reindex / putScript /
// scriptsPainlessExecute) are tagged as SnkEval (CWE-94) because tainted
// script source = arbitrary code execution on the cluster.
//
// Mirror of tsflow_python_elasticsearch_test.go.
// =========================================================================

func TestJS_Elasticsearch_Bulk_DSLInjection(t *testing.T) {
	code := `
const { Client } = require('@elastic/elasticsearch');
const client = new Client({ node: 'http://localhost:9200' });

function bulkIndex(req, res) {
    const ops = req.body.operations;
    return client.bulk({ body: ops });
}
`
	flows := Analyze(code, "/app/handlers/bulk.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.elasticsearch.bulk") {
		t.Error("expected js.elasticsearch.bulk flow from req.body -> client.bulk()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJS_Elasticsearch_MSearch_DSLInjection(t *testing.T) {
	code := `
const { Client } = require('@elastic/elasticsearch');
const client = new Client({ node: 'http://localhost:9200' });

async function multiSearch(req, res) {
    const term = req.query.term;
    const body = [
        { index: 'logs' },
        { query: { match: { message: term } } }
    ];
    return await client.msearch({ body: body });
}
`
	flows := Analyze(code, "/app/handlers/msearch.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.elasticsearch.msearch") {
		t.Error("expected js.elasticsearch.msearch flow from req.query -> client.msearch()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJS_Elasticsearch_DeleteByQuery_DSLInjection(t *testing.T) {
	code := `
const { Client } = require('@elastic/elasticsearch');
const client = new Client({ node: 'http://localhost:9200' });

async function purge(req, res) {
    const tag = req.body.tag;
    return await client.deleteByQuery({
        index: 'items',
        body: { query: { match: { tag: tag } } }
    });
}
`
	flows := Analyze(code, "/app/handlers/purge.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.elasticsearch.deletebyquery") {
		t.Error("expected js.elasticsearch.deletebyquery flow from req.body -> client.deleteByQuery()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJS_Elasticsearch_UpdateByQuery_PainlessRCE(t *testing.T) {
	code := `
const { Client } = require('@elastic/elasticsearch');
const client = new Client({ node: 'http://localhost:9200' });

async function bulkUpdate(req, res) {
    const src = req.body.script_source;
    return await client.updateByQuery({
        index: 'items',
        body: {
            script: { source: src, lang: 'painless' },
            query: { match_all: {} }
        }
    });
}
`
	flows := Analyze(code, "/app/handlers/update.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.elasticsearch.updatebyquery") {
		t.Error("expected js.elasticsearch.updatebyquery flow from req.body -> client.updateByQuery()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJS_Elasticsearch_Reindex_PainlessRCE(t *testing.T) {
	code := `
const { Client } = require('@elastic/elasticsearch');
const client = new Client({ node: 'http://localhost:9200' });

async function reindexDocs(req, res) {
    const src = req.body.transform;
    return await client.reindex({
        body: {
            source: { index: 'old' },
            dest: { index: 'new' },
            script: { source: src, lang: 'painless' }
        }
    });
}
`
	flows := Analyze(code, "/app/handlers/reindex.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.elasticsearch.reindex") {
		t.Error("expected js.elasticsearch.reindex flow from req.body -> client.reindex()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJS_Elasticsearch_PutScript_StoredPainlessRCE(t *testing.T) {
	code := `
const { Client } = require('@elastic/elasticsearch');
const client = new Client({ node: 'http://localhost:9200' });

async function saveScript(req, res) {
    const src = req.body.src;
    return await client.putScript({
        id: 'calc',
        body: { script: { source: src, lang: 'painless' } }
    });
}
`
	flows := Analyze(code, "/app/handlers/script.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.elasticsearch.putscript") {
		t.Error("expected js.elasticsearch.putscript flow from req.body -> client.putScript()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJS_Elasticsearch_ScriptsPainlessExecute_DirectRCE(t *testing.T) {
	code := `
const { Client } = require('@elastic/elasticsearch');
const client = new Client({ node: 'http://localhost:9200' });

async function runScript(req, res) {
    const src = req.body.source;
    return await client.scriptsPainlessExecute({
        body: { script: { source: src, lang: 'painless' } }
    });
}
`
	flows := Analyze(code, "/app/handlers/painless.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.elasticsearch.scriptspainlessexecute") {
		t.Error("expected js.elasticsearch.scriptspainlessexecute flow from req.body -> client.scriptsPainlessExecute()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- OpenSearch coverage: same JS client API ---

func TestJS_OpenSearch_DeleteByQuery_DSLInjection(t *testing.T) {
	code := `
const { Client } = require('@opensearch-project/opensearch');
const client = new Client({ node: 'http://localhost:9200' });

async function purge(req, res) {
    const tag = req.body.tag;
    return await client.deleteByQuery({
        index: 'items',
        body: { query: { match: { tag: tag } } }
    });
}
`
	flows := Analyze(code, "/app/handlers/os_purge.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.elasticsearch.deletebyquery") {
		t.Error("expected js.elasticsearch.deletebyquery flow on OpenSearch client (shared sink set)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Negative tests: safe usage should NOT produce ES sink findings ---

func TestJS_Elasticsearch_Hardcoded_NoFlow(t *testing.T) {
	code := `
const { Client } = require('@elastic/elasticsearch');
const client = new Client({ node: 'http://localhost:9200' });

async function countAll() {
    return await client.bulk({
        body: [
            { index: { _index: 'logs' } },
            { message: 'static log' }
        ]
    });
}
`
	flows := Analyze(code, "/app/lib/seed.js", rules.LangJavaScript)
	if flowMatchesSinkID(flows, "js.elasticsearch.bulk") {
		t.Error("expected NO js.elasticsearch.bulk flow for fully-hardcoded body")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}
