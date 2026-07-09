package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Java Elasticsearch / OpenSearch query-DSL + Painless injection tests
// (CWE-943 / CWE-94). Covers the three main Java client families:
//   - High-level REST client: QueryBuilders.* static builders
//   - Low-level REST client: Request.setJsonEntity(rawJson)
//   - Elasticsearch Java API Client (8.x): client.updateByQuery/msearch/...
// Plus Spring Data Elasticsearch new StringQuery(rawJson).
// =========================================================================

// --- QueryBuilders.wrapperQuery: raw JSON query DSL ---

func TestJava_Elasticsearch_WrapperQuery_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.index.query.WrapperQueryBuilder;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String filter = request.getParameter("filter");
        WrapperQueryBuilder q = QueryBuilders.wrapperQuery(filter);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected DSL-injection flow for getParameter -> QueryBuilders.wrapperQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- QueryBuilders.queryStringQuery: Lucene operator injection ---

func TestJava_Elasticsearch_QueryStringQuery_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.index.query.QueryStringQueryBuilder;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String term = request.getParameter("q");
        QueryStringQueryBuilder q = QueryBuilders.queryStringQuery(term);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Lucene-injection flow for getParameter -> QueryBuilders.queryStringQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- QueryBuilders.simpleQueryStringQuery: simplified Lucene injection ---

func TestJava_Elasticsearch_SimpleQueryStringQuery_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.elasticsearch.index.query.QueryBuilders;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String term = request.getParameter("q");
        Object q = QueryBuilders.simpleQueryStringQuery(term);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Lucene-injection flow for getParameter -> QueryBuilders.simpleQueryStringQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- QueryBuilders.scriptQuery with tainted Painless source: RCE on ES cluster ---

func TestJava_Elasticsearch_ScriptQuery_PainlessRCE(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.script.Script;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String source = request.getParameter("painless");
        Object q = QueryBuilders.scriptQuery(new Script(source));
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected Painless-RCE flow for getParameter -> QueryBuilders.scriptQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Low-level REST client: Request.setJsonEntity(raw JSON) ---

func TestJava_Elasticsearch_Request_SetJsonEntity_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.elasticsearch.client.Request;
import org.elasticsearch.client.RestClient;

public class Handler extends HttpServlet {
    private RestClient restClient;
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String body = request.getParameter("body");
        Request esReq = new Request("POST", "/logs/_search");
        esReq.setJsonEntity(body);
        restClient.performRequest(esReq);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected DSL-injection flow for getParameter -> Request.setJsonEntity")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- ES Java API Client 8.x: client.updateByQuery (Painless + DSL body) ---

func TestJava_Elasticsearch_UpdateByQuery_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import co.elastic.clients.elasticsearch.ElasticsearchClient;
import co.elastic.clients.elasticsearch.core.UpdateByQueryRequest;

public class Handler extends HttpServlet {
    private ElasticsearchClient client;
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String script = request.getParameter("script");
        UpdateByQueryRequest req = UpdateByQueryRequest.of(u -> u
            .index("items")
            .script(s -> s.inline(i -> i.lang("painless").source(script)))
        );
        client.updateByQuery(req);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected Painless-RCE flow for getParameter -> client.updateByQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- ES Java API Client 8.x: client.deleteByQuery (DSL injection) ---

func TestJava_Elasticsearch_DeleteByQuery_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import co.elastic.clients.elasticsearch.ElasticsearchClient;
import co.elastic.clients.elasticsearch.core.DeleteByQueryRequest;

public class Handler extends HttpServlet {
    private ElasticsearchClient client;
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String tag = request.getParameter("tag");
        DeleteByQueryRequest req = DeleteByQueryRequest.of(d -> d
            .index("items")
            .query(q -> q.term(t -> t.field("tag").value(tag)))
        );
        client.deleteByQuery(req);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	// Elasticsearch deleteByQuery is a NoSQL DSL-injection sink (CWE-943,
	// SnkNoSQL via java.elasticsearch.client.deletebyquery), matching its
	// sibling client.msearch test below. The assertion previously read
	// SnkSQLQuery and passed only because a catch-all `.query()` SQL sink
	// mis-classified the builder's inner .query(q -> ...) call as CWE-89;
	// that catch-all is now tightened (GAP-java PART A), so assert the real
	// NoSQL category.
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL DSL-injection flow for getParameter -> client.deleteByQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- ES Java API Client 8.x: client.msearch (NDJSON body) ---

func TestJava_Elasticsearch_Msearch_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import co.elastic.clients.elasticsearch.ElasticsearchClient;
import co.elastic.clients.elasticsearch.core.MsearchRequest;

public class Handler extends HttpServlet {
    private ElasticsearchClient client;
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String ndjson = request.getParameter("ndjson");
        MsearchRequest req = MsearchRequest.of(m -> m.withJson(new java.io.StringReader(ndjson)));
        client.msearch(req, Object.class);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected DSL-injection flow for getParameter -> client.msearch")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- ES Java API Client 8.x: client.scriptsPainlessExecute (direct RCE) ---

func TestJava_Elasticsearch_ScriptsPainlessExecute_RCE(t *testing.T) {
	code := `
import javax.servlet.http.*;
import co.elastic.clients.elasticsearch.ElasticsearchClient;
import co.elastic.clients.elasticsearch.painless_execute.PainlessExecuteRequest;

public class Handler extends HttpServlet {
    private ElasticsearchClient client;
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String source = request.getParameter("source");
        PainlessExecuteRequest req = PainlessExecuteRequest.of(p -> p
            .script(s -> s.inline(i -> i.lang("painless").source(source)))
        );
        client.scriptsPainlessExecute(req, Object.class);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected Painless-RCE flow for getParameter -> client.scriptsPainlessExecute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- ES Java API Client 8.x: client.putScript (persistent Painless) ---

func TestJava_Elasticsearch_PutScript_Persistent_RCE(t *testing.T) {
	code := `
import javax.servlet.http.*;
import co.elastic.clients.elasticsearch.ElasticsearchClient;
import co.elastic.clients.elasticsearch.core.PutScriptRequest;

public class Handler extends HttpServlet {
    private ElasticsearchClient client;
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String source = request.getParameter("source");
        PutScriptRequest req = PutScriptRequest.of(p -> p
            .id("my-stored-script")
            .script(s -> s.lang("painless").source(source))
        );
        client.putScript(req);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected Painless-RCE flow for getParameter -> client.putScript")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Spring Data Elasticsearch: new StringQuery(rawJson) ---

func TestJava_Elasticsearch_Spring_StringQuery_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.springframework.data.elasticsearch.core.ElasticsearchOperations;
import org.springframework.data.elasticsearch.core.query.StringQuery;

public class Handler extends HttpServlet {
    private ElasticsearchOperations ops;
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String json = request.getParameter("q");
        StringQuery q = new StringQuery(json);
        ops.search(q, Object.class);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected DSL-injection flow for getParameter -> new StringQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// =========================================================================
// Negative tests: safe usage should NOT produce ES sink findings
// =========================================================================

// Typed termQuery (safe — values are bound, not interpolated)

func TestJava_Elasticsearch_TermQuery_Safe_NoFlow(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.elasticsearch.index.query.QueryBuilders;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String user = request.getParameter("user");
        // termQuery passes the user value as a bound field value, not as query DSL
        Object q = QueryBuilders.termQuery("username", user);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	for _, f := range flows {
		if f.Sink.ID == "java.elasticsearch.querybuilders.wrapperquery" ||
			f.Sink.ID == "java.elasticsearch.querybuilders.querystringquery" ||
			f.Sink.ID == "java.elasticsearch.querybuilders.simplequerystringquery" ||
			f.Sink.ID == "java.elasticsearch.querybuilders.scriptquery" {
			t.Errorf("expected NO ES DSL-injection flow for termQuery (bound field), got sink %s", f.Sink.ID)
		}
	}
}

// Hardcoded wrapperQuery (no source taint) — should produce no flow

func TestJava_Elasticsearch_WrapperQuery_Hardcoded_NoFlow(t *testing.T) {
	code := `
import org.elasticsearch.index.query.QueryBuilders;

public class Handler {
    public void run() {
        Object q = QueryBuilders.wrapperQuery("{\"match_all\":{}}");
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	for _, f := range flows {
		if f.Sink.ID == "java.elasticsearch.querybuilders.wrapperquery" {
			t.Errorf("expected NO flow for hardcoded wrapperQuery literal, got %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
