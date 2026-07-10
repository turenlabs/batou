package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Java Apache Solr (SolrJ) query-DSL injection (CWE-943) and parameter-name
// injection (CWE-94 — Velocity-template RCE per CVE-2019-17558, request-handler
// hijack via qt, /shards SSRF per CVE-2017-3164). SolrJ is the dominant Java
// client used by Drupal, Magento, Liferay, and most enterprise CMS stacks.
// =========================================================================

// --- new SolrQuery(q): tainted q parameter at construction (CWE-943) ---

func TestJava_Solr_SolrQuery_New_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.apache.solr.client.solrj.SolrClient;
import org.apache.solr.client.solrj.SolrQuery;
import org.apache.solr.client.solrj.response.QueryResponse;

public class Handler extends HttpServlet {
    private SolrClient solrClient;
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String input = request.getParameter("q");
        SolrQuery solrQuery = new SolrQuery(input);
        QueryResponse rsp = solrClient.query(solrQuery);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	// new SolrQuery(q) is a NoSQL/Lucene DSL-injection sink (CWE-943,
	// SnkNoSQL via java.solr.solrquery.new), matching the sibling
	// SetQuery/AddFilterQuery tests. The assertion previously read
	// SnkSQLQuery and passed only because a catch-all `.query()` SQL sink
	// mis-classified solrClient.query(solrQuery) as CWE-89; that catch-all
	// is now tightened (GAP-java PART A), so assert the real NoSQL category.
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Solr DSL-injection flow for getParameter -> new SolrQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- SolrQuery.setQuery(q): tainted q parameter (CWE-943) ---

func TestJava_Solr_SolrQuery_SetQuery_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.apache.solr.client.solrj.SolrQuery;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String input = request.getParameter("q");
        SolrQuery solrQuery = new SolrQuery();
        solrQuery.setQuery(input);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Solr DSL-injection flow for getParameter -> SolrQuery.setQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- SolrQuery.set(name, value): tainted param name targets v.template / qt / shards (CWE-94) ---

func TestJava_Solr_SolrQuery_Set_VelocityTemplateRCE(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.apache.solr.client.solrj.SolrQuery;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String input = request.getParameter("template");
        SolrQuery solrQuery = new SolrQuery("*:*");
        solrQuery.set("v.template", input);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected Solr Velocity-template RCE flow (CVE-2019-17558) for getParameter -> SolrQuery.set")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- SolrQuery.setParam(name, value): tainted shards param triggers SSRF (CVE-2017-3164) ---

func TestJava_Solr_SolrQuery_SetParam_ShardsSSRF(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.apache.solr.client.solrj.SolrQuery;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String input = request.getParameter("shards");
        SolrQuery solrQuery = new SolrQuery("*:*");
        solrQuery.setParam("shards", input);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected Solr shards-SSRF flow (CVE-2017-3164) for getParameter -> SolrQuery.setParam")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- SolrQuery.addFilterQuery(fq): tainted fq DSL (CWE-943) ---

func TestJava_Solr_SolrQuery_AddFilterQuery_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.apache.solr.client.solrj.SolrQuery;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String input = request.getParameter("filter");
        SolrQuery solrQuery = new SolrQuery("*:*");
        solrQuery.addFilterQuery(input);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Solr fq-injection flow for getParameter -> SolrQuery.addFilterQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- SolrQuery.setFilterQueries(fq...): tainted varargs (CWE-943) ---

func TestJava_Solr_SolrQuery_SetFilterQueries_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.apache.solr.client.solrj.SolrQuery;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String input = request.getParameter("filters");
        SolrQuery solrQuery = new SolrQuery("*:*");
        solrQuery.setFilterQueries(input);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Solr fq-injection flow for getParameter -> SolrQuery.setFilterQueries")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- SolrQuery.setRequestHandler(handler): tainted qt routes to /admin/* (CWE-94) ---

func TestJava_Solr_SolrQuery_SetRequestHandler_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.apache.solr.client.solrj.SolrQuery;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String input = request.getParameter("handler");
        SolrQuery solrQuery = new SolrQuery("*:*");
        solrQuery.setRequestHandler(input);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected Solr handler-hijack flow for getParameter -> SolrQuery.setRequestHandler")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// =========================================================================
// Negative tests: safe usage should NOT produce Solr-sink findings
// =========================================================================

// ClientUtils.escapeQueryChars sanitizes user input before composing q

func TestJava_Solr_SolrQuery_EscapedQuery_NoFlow(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.apache.solr.client.solrj.SolrQuery;
import org.apache.solr.client.solrj.util.ClientUtils;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String input = request.getParameter("q");
        String safe = ClientUtils.escapeQueryChars(input);
        SolrQuery solrQuery = new SolrQuery();
        solrQuery.setQuery("title:" + safe);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	for _, f := range flows {
		if f.Sink.ID == "java.solr.solrquery.setquery" || f.Sink.ID == "java.solr.solrquery.new" {
			t.Errorf("expected NO Solr DSL-injection flow when ClientUtils.escapeQueryChars is applied, got %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// Hardcoded literal q (no source taint)

func TestJava_Solr_SolrQuery_Hardcoded_NoFlow(t *testing.T) {
	code := `
import org.apache.solr.client.solrj.SolrQuery;

public class Handler {
    public void run() {
        SolrQuery solrQuery = new SolrQuery("*:*");
        solrQuery.setQuery("title:cat AND status:active");
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	for _, f := range flows {
		if f.Sink.ID == "java.solr.solrquery.setquery" ||
			f.Sink.ID == "java.solr.solrquery.new" ||
			f.Sink.ID == "java.solr.solrquery.addfilterquery" {
			t.Errorf("expected NO flow for hardcoded SolrQuery literals, got %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}
