package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// ---------- Elasticsearch / OpenSearch query-DSL + Painless script injection ----------
//
// Kotlin uses the official Elasticsearch Java drivers (high-level REST,
// low-level REST, Java API Client 8.x) and Spring Data Elasticsearch.
// All accept user-built query DSL or Painless scripts; tainted strings
// allow query-structure injection or remote code execution on the cluster.
// OpenSearch ships a near-identical driver API; the same patterns apply.

// ---------- QueryBuilders.wrapperQuery (CWE-943) ----------

func TestKotlin_Elasticsearch_QueryBuilders_WrapperQuery_Injection(t *testing.T) {
	code := `
import org.elasticsearch.index.query.QueryBuilders

fun search(input: String) {
    val json = "{\"term\":{\"field\":\"" + input + "\"}}"
    val q = QueryBuilders.wrapperQuery(json)
}
`
	flows := Analyze(code, "/app/SearchDao.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.ID == "kotlin.elasticsearch.querybuilders.wrapperquery" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected ES DSL injection on QueryBuilders.wrapperQuery; got flows: %+v", flows)
	}
}

// ---------- QueryBuilders.queryStringQuery (CWE-943) ----------

func TestKotlin_Elasticsearch_QueryBuilders_QueryStringQuery_Injection(t *testing.T) {
	code := `
import org.elasticsearch.index.query.QueryBuilders

fun search(input: String) {
    val q = QueryBuilders.queryStringQuery("name:" + input)
}
`
	flows := Analyze(code, "/app/SearchDao.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.ID == "kotlin.elasticsearch.querybuilders.querystringquery" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected ES Lucene injection on QueryBuilders.queryStringQuery; got flows: %+v", flows)
	}
}

// ---------- QueryBuilders.simpleQueryStringQuery (CWE-943) ----------

func TestKotlin_Elasticsearch_QueryBuilders_SimpleQueryStringQuery_Injection(t *testing.T) {
	code := `
import org.elasticsearch.index.query.QueryBuilders

fun search(input: String) {
    val q = QueryBuilders.simpleQueryStringQuery("title:" + input + " | body:" + input)
}
`
	flows := Analyze(code, "/app/SearchDao.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.ID == "kotlin.elasticsearch.querybuilders.simplequerystringquery" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected ES Lucene injection on QueryBuilders.simpleQueryStringQuery; got flows: %+v", flows)
	}
}

// ---------- QueryBuilders.scriptQuery — Painless RCE (CWE-94) ----------

func TestKotlin_Elasticsearch_QueryBuilders_ScriptQuery_PainlessRCE(t *testing.T) {
	code := `
import org.elasticsearch.index.query.QueryBuilders
import org.elasticsearch.script.Script

fun filterDocs(input: String) {
    val script = Script("doc['field'].value == '" + input + "'")
    val q = QueryBuilders.scriptQuery(script)
}
`
	flows := Analyze(code, "/app/SearchDao.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.ID == "kotlin.elasticsearch.querybuilders.scriptquery" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected Painless RCE on QueryBuilders.scriptQuery; got flows: %+v", flows)
	}
}

// ---------- Request.setJsonEntity — low-level REST DSL injection (CWE-943) ----------

func TestKotlin_Elasticsearch_Request_SetJsonEntity_Injection(t *testing.T) {
	code := `
import org.elasticsearch.client.Request

fun runRaw(client: org.elasticsearch.client.RestClient, input: String) {
    val req = Request("POST", "/my-index/_search")
    val body = "{\"query\":{\"match\":{\"x\":\"" + input + "\"}}}"
    req.setJsonEntity(body)
    client.performRequest(req)
}
`
	flows := Analyze(code, "/app/RestDao.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.ID == "kotlin.elasticsearch.request.setjsonentity" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected DSL injection on Request.setJsonEntity; got flows: %+v", flows)
	}
}

// ---------- client.updateByQuery — Painless RCE (CWE-94) ----------

func TestKotlin_Elasticsearch_Client_UpdateByQuery_PainlessRCE(t *testing.T) {
	code := `
fun bulkUpdate(client: org.elasticsearch.client.RestHighLevelClient, input: String) {
    val req = org.elasticsearch.index.reindex.UpdateByQueryRequest("idx")
    req.setQuery(org.elasticsearch.index.query.QueryBuilders.queryStringQuery(input))
    client.updateByQuery(req, org.elasticsearch.client.RequestOptions.DEFAULT)
}
`
	flows := Analyze(code, "/app/UpdateDao.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.ID == "kotlin.elasticsearch.client.updatebyquery" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected Painless RCE / DSL injection on client.updateByQuery; got flows: %+v", flows)
	}
}

// ---------- client.deleteByQuery — bulk destructive DSL injection (CWE-943) ----------

func TestKotlin_Elasticsearch_Client_DeleteByQuery_Injection(t *testing.T) {
	code := `
fun cleanup(client: org.elasticsearch.client.RestHighLevelClient, input: String) {
    val req = org.elasticsearch.index.reindex.DeleteByQueryRequest("logs")
    req.setQuery(org.elasticsearch.index.query.QueryBuilders.queryStringQuery("user:" + input))
    client.deleteByQuery(req, org.elasticsearch.client.RequestOptions.DEFAULT)
}
`
	flows := Analyze(code, "/app/CleanupDao.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.ID == "kotlin.elasticsearch.client.deletebyquery" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected destructive DSL injection on client.deleteByQuery; got flows: %+v", flows)
	}
}

// ---------- client.msearch — multi-search NDJSON DSL injection (CWE-943) ----------

func TestKotlin_Elasticsearch_Client_MultiSearch_Injection(t *testing.T) {
	code := `
fun multi(client: org.elasticsearch.client.RestHighLevelClient, input: String) {
    val req = org.elasticsearch.action.search.MultiSearchRequest()
    req.add(org.elasticsearch.action.search.SearchRequest().source(
        org.elasticsearch.search.builder.SearchSourceBuilder().query(
            org.elasticsearch.index.query.QueryBuilders.queryStringQuery(input))))
    client.msearch(req, org.elasticsearch.client.RequestOptions.DEFAULT)
}
`
	flows := Analyze(code, "/app/MultiDao.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.ID == "kotlin.elasticsearch.client.msearch" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected DSL injection on client.msearch; got flows: %+v", flows)
	}
}

// ---------- client.scriptsPainlessExecute — direct Painless RCE (CWE-94) ----------

func TestKotlin_Elasticsearch_Client_ScriptsPainlessExecute_RCE(t *testing.T) {
	code := `
fun execScript(client: org.elasticsearch.client.RestHighLevelClient, input: String) {
    val req = "{\"script\":{\"source\":\"" + input + "\"}}"
    client.scriptsPainlessExecute(req, org.elasticsearch.client.RequestOptions.DEFAULT)
}
`
	flows := Analyze(code, "/app/PainlessDao.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.ID == "kotlin.elasticsearch.client.scriptspainlessexecute" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected Painless RCE on client.scriptsPainlessExecute; got flows: %+v", flows)
	}
}

// ---------- client.putScript — persistent stored Painless RCE (CWE-94) ----------

func TestKotlin_Elasticsearch_Client_PutScript_PersistentRCE(t *testing.T) {
	code := `
fun storeScript(client: org.elasticsearch.client.RestHighLevelClient, input: String) {
    val body = "{\"script\":{\"lang\":\"painless\",\"source\":\"" + input + "\"}}"
    client.putScript(body, org.elasticsearch.client.RequestOptions.DEFAULT)
}
`
	flows := Analyze(code, "/app/StoreScriptDao.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.ID == "kotlin.elasticsearch.client.putscript" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected persistent Painless RCE on client.putScript; got flows: %+v", flows)
	}
}

// ---------- Spring Data Elasticsearch StringQuery (CWE-943) ----------
// Kotlin invokes constructors without `new`: val q = StringQuery(json)

func TestKotlin_Elasticsearch_Spring_StringQuery_Injection(t *testing.T) {
	code := `
import org.springframework.data.elasticsearch.core.query.StringQuery

fun runQuery(input: String) {
    val json = "{\"match\":{\"f\":\"" + input + "\"}}"
    val q = StringQuery(json)
}
`
	flows := Analyze(code, "/app/SpringEsDao.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.ID == "kotlin.spring.elasticsearch.stringquery.new" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected Spring Data ES StringQuery DSL injection; got flows: %+v", flows)
	}
}

// ---------- Safe: typed termQuery with hardcoded field, parameter as value ----------
// Using QueryBuilders.termQuery (typed, value bound) is safe — no DSL injection.
func TestKotlin_Elasticsearch_TypedTermQuery_Safe(t *testing.T) {
	code := `
import org.elasticsearch.index.query.QueryBuilders

fun search(input: String) {
    val q = QueryBuilders.termQuery("user.id", input)
}
`
	flows := Analyze(code, "/app/SafeDao.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.ID == "kotlin.elasticsearch.querybuilders.wrapperquery" ||
			f.Sink.ID == "kotlin.elasticsearch.querybuilders.querystringquery" ||
			f.Sink.ID == "kotlin.elasticsearch.querybuilders.simplequerystringquery" ||
			f.Sink.ID == "kotlin.elasticsearch.querybuilders.scriptquery" {
			t.Errorf("Unexpected ES DSL finding on typed termQuery: %+v", f)
		}
	}
}
