package tsflow

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// C# Elasticsearch / OpenSearch DSL + Painless / Mustache template
// injection tests (CWE-943, CWE-94).
//
// Covers the three first-party C# clients that share the same auto-generated
// method surface:
//
//   - NEST v7              — Nest.ElasticClient + Elasticsearch.Net.IElasticLowLevelClient
//   - Elastic.Clients.Elasticsearch v8 — ElasticsearchClient (replaces NEST)
//   - OpenSearch.Client v1+ — OpenSearch.Client.OpenSearchClient
//
// All three expose distinctive method names — Msearch, DeleteByQuery,
// UpdateByQuery, Reindex, SearchTemplate, RenderSearchTemplate,
// ScriptsPainlessExecute, PutScript — that don't collide with stdlib or
// other ORMs / message brokers, so the catalog uses ObjectType "" with
// usage-based DangerousArgs []int{-1}.
// =========================================================================

func findFlowByID(flows []taint.TaintFlow, id string) bool {
	for _, f := range flows {
		if f.Sink.ID == id {
			return true
		}
	}
	return false
}

// -------------------------------------------------------------------------
// Catalog wiring assertion — fast feedback when an entry is dropped or
// renamed accidentally during refactors.
// -------------------------------------------------------------------------

func TestCSharp_Elasticsearch_SinksRegistered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangCSharp)
	if cat == nil {
		t.Fatal("C# catalog not loaded")
	}
	have := map[string]bool{}
	for _, s := range cat.Sinks() {
		have[s.ID] = true
	}
	expected := []string{
		"csharp.elasticsearch.client.msearch",
		"csharp.elasticsearch.client.deletebyquery",
		"csharp.elasticsearch.client.updatebyquery",
		"csharp.elasticsearch.client.reindex",
		"csharp.elasticsearch.client.searchtemplate",
		"csharp.elasticsearch.client.rendersearchtemplate",
		"csharp.elasticsearch.client.scriptspainlessexecute",
		"csharp.elasticsearch.client.putscript",
	}
	for _, id := range expected {
		if !have[id] {
			t.Errorf("expected sink %q to be registered", id)
		}
	}
}

// -------------------------------------------------------------------------
// Positive flows: tainted user input → ES/OS sink methods.
// All tests use Console.ReadLine() (csharp.console.readline) as the
// canonical user-input source, mirroring the existing
// tsflow_csharp_cassandra_test.go convention.
// -------------------------------------------------------------------------

func TestCSharp_Elasticsearch_Msearch_TaintedNDJSON(t *testing.T) {
	// NEST v7 LowLevel.Msearch with a tainted PostData.String body —
	// the canonical NDJSON-injection escape hatch when callers want to
	// hand-build the request body.
	code := `
using System;
using Elasticsearch.Net;
using Nest;

public class Handler {
    public void Handle(IElasticClient client) {
        string input = Console.ReadLine();
        var resp = client.LowLevel.Msearch<StringResponse>(PostData.String(input));
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !findFlowByID(flows, "csharp.elasticsearch.client.msearch") {
		t.Error("expected csharp.elasticsearch.client.msearch flow for Console.ReadLine -> LowLevel.Msearch")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCSharp_Elasticsearch_MsearchAsync_TaintedNDJSON(t *testing.T) {
	// Async variant — the Async suffix should be matched via the
	// compound MethodName "MsearchAsync/Msearch".
	code := `
using System;
using System.Threading.Tasks;
using Elasticsearch.Net;
using Nest;

public class Handler {
    public async Task Handle(IElasticClient client) {
        string body = Console.ReadLine();
        var resp = await client.LowLevel.MsearchAsync<StringResponse>(PostData.String(body));
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !findFlowByID(flows, "csharp.elasticsearch.client.msearch") {
		t.Error("expected csharp.elasticsearch.client.msearch flow for Console.ReadLine -> MsearchAsync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCSharp_Elasticsearch_DeleteByQuery_TaintedFilter(t *testing.T) {
	// DeleteByQuery: tainted filter body lets an attacker delete documents
	// outside the intended scope (CWE-943) — destructive amplifier.
	code := `
using System;
using System.Threading.Tasks;
using Elasticsearch.Net;
using Nest;

public class Handler {
    public async Task Handle(IElasticClient client) {
        string payload = Console.ReadLine();
        var resp = await client.LowLevel.DeleteByQueryAsync<StringResponse>("docs", PostData.String(payload));
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !findFlowByID(flows, "csharp.elasticsearch.client.deletebyquery") {
		t.Error("expected csharp.elasticsearch.client.deletebyquery flow for Console.ReadLine -> DeleteByQueryAsync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCSharp_Elasticsearch_UpdateByQuery_TaintedPainless(t *testing.T) {
	// UpdateByQuery body accepts a Painless `script.source`; tainted source
	// = arbitrary Painless code execution on the cluster (CWE-94 RCE class).
	code := `
using System;
using System.Threading.Tasks;
using Elasticsearch.Net;
using Nest;

public class Handler {
    public async Task Handle(IElasticClient client) {
        string input = Console.ReadLine();
        var resp = await client.LowLevel.UpdateByQueryAsync<StringResponse>("docs", PostData.String(input));
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !findFlowByID(flows, "csharp.elasticsearch.client.updatebyquery") {
		t.Error("expected csharp.elasticsearch.client.updatebyquery flow for Console.ReadLine -> UpdateByQueryAsync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCSharp_Elasticsearch_Reindex_TaintedScript(t *testing.T) {
	// Reindex body accepts a Painless script.source plus tainted source/dest
	// selectors — Painless RCE plus cross-index data exfiltration.
	code := `
using System;
using System.Threading.Tasks;
using Elasticsearch.Net;
using Nest;

public class Handler {
    public async Task Handle(IElasticClient client) {
        string input = Console.ReadLine();
        var resp = await client.LowLevel.ReindexOnServerAsync<StringResponse>(PostData.String(input));
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !findFlowByID(flows, "csharp.elasticsearch.client.reindex") {
		t.Error("expected csharp.elasticsearch.client.reindex flow for Console.ReadLine -> ReindexOnServerAsync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCSharp_Elasticsearch_SearchTemplate_TaintedMustache(t *testing.T) {
	// SearchTemplate body accepts an inline Mustache template source —
	// tainted source = template-source injection that compiles to
	// attacker-shaped queries (CWE-94).
	code := `
using System;
using System.Threading.Tasks;
using Elasticsearch.Net;
using Nest;

public class Handler {
    public async Task Handle(IElasticClient client) {
        string body = Console.ReadLine();
        var resp = await client.LowLevel.SearchTemplateAsync<StringResponse>("idx", PostData.String(body));
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !findFlowByID(flows, "csharp.elasticsearch.client.searchtemplate") {
		t.Error("expected csharp.elasticsearch.client.searchtemplate flow for Console.ReadLine -> SearchTemplateAsync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCSharp_Elasticsearch_RenderSearchTemplate_Tainted(t *testing.T) {
	code := `
using System;
using System.Threading.Tasks;
using Elasticsearch.Net;
using Nest;

public class Handler {
    public async Task Handle(IElasticClient client) {
        string payload = Console.ReadLine();
        var resp = await client.LowLevel.RenderSearchTemplateAsync<StringResponse>(PostData.String(payload));
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !findFlowByID(flows, "csharp.elasticsearch.client.rendersearchtemplate") {
		t.Error("expected csharp.elasticsearch.client.rendersearchtemplate flow for Console.ReadLine -> RenderSearchTemplateAsync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCSharp_Elasticsearch_ScriptsPainlessExecute_TaintedPainless(t *testing.T) {
	// ScriptsPainlessExecute runs an ad-hoc Painless script on the
	// cluster — tainted body = remote Painless code evaluation (CWE-94).
	code := `
using System;
using System.Threading.Tasks;
using Elasticsearch.Net;
using Nest;

public class Handler {
    public async Task Handle(IElasticClient client) {
        string input = Console.ReadLine();
        var resp = await client.LowLevel.ScriptsPainlessExecuteAsync<StringResponse>(PostData.String(input));
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !findFlowByID(flows, "csharp.elasticsearch.client.scriptspainlessexecute") {
		t.Error("expected csharp.elasticsearch.client.scriptspainlessexecute flow for Console.ReadLine -> ScriptsPainlessExecuteAsync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCSharp_Elasticsearch_PutScript_TaintedPainless(t *testing.T) {
	// PutScript persists a tainted Painless script under a stored ID —
	// every later request that invokes that ID executes attacker code.
	code := `
using System;
using System.Threading.Tasks;
using Elasticsearch.Net;
using Nest;

public class Handler {
    public async Task Handle(IElasticClient client) {
        string body = Console.ReadLine();
        var resp = await client.LowLevel.PutScriptAsync<StringResponse>("attacker_script", PostData.String(body));
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !findFlowByID(flows, "csharp.elasticsearch.client.putscript") {
		t.Error("expected csharp.elasticsearch.client.putscript flow for Console.ReadLine -> PutScriptAsync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

// -------------------------------------------------------------------------
// OpenSearch parity — OpenSearch.Client.OpenSearchClient is a NEST fork
// and exposes the exact same method names (Msearch, DeleteByQuery, etc.).
// The same catalog entries should fire on OpenSearch code without a
// dedicated `csharp.opensearch.*` ID. This test confirms the entry is
// truly OpenSearch-compatible (i.e. ObjectType "" wasn't accidentally
// scoped to a NEST-only receiver name).
// -------------------------------------------------------------------------

func TestCSharp_OpenSearch_DeleteByQuery_TaintedFilter(t *testing.T) {
	code := `
using System;
using System.Threading.Tasks;
using OpenSearch.Client;
using OpenSearch.Net;

public class Handler {
    public async Task Handle(IOpenSearchClient osClient) {
        string input = Console.ReadLine();
        var resp = await osClient.LowLevel.DeleteByQueryAsync<StringResponse>("docs", PostData.String(input));
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !findFlowByID(flows, "csharp.elasticsearch.client.deletebyquery") {
		t.Error("expected csharp.elasticsearch.client.deletebyquery flow for OpenSearch IOpenSearchClient.LowLevel.DeleteByQueryAsync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

// -------------------------------------------------------------------------
// Negative test: literal-only body (no taint) must NOT fire. This catches
// the catastrophic ObjectType "" + generic-method-name regression class
// where a sink would fire on every .DeleteByQuery(...) regardless of arg
// taintedness — ensuring DangerousArgs []int{-1} is honoured by the walker.
// -------------------------------------------------------------------------

func TestCSharp_Elasticsearch_DeleteByQuery_HardcodedBody_NoFlow(t *testing.T) {
	code := `
using System;
using System.Threading.Tasks;
using Elasticsearch.Net;
using Nest;

public class Handler {
    public async Task Handle(IElasticClient client) {
        string safeBody = "{\"query\":{\"match_all\":{}}}";
        var resp = await client.LowLevel.DeleteByQueryAsync<StringResponse>("docs", PostData.String(safeBody));
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if strings.HasPrefix(f.Sink.ID, "csharp.elasticsearch.") {
			t.Errorf("unexpected ES flow on a hardcoded body: id=%s", f.Sink.ID)
		}
	}
}
