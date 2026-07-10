package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// C++ database source tests
// =========================================================================

func TestCPP_SQLite3_StoredCommandInjection(t *testing.T) {
	code := `
#include <sqlite3.h>
#include <cstdlib>

void handler() {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    sqlite3_open("app.db", &db);
    sqlite3_prepare_v2(db, "SELECT cmd FROM jobs WHERE id=1", -1, &stmt, NULL);
    sqlite3_step(stmt);
    auto cmd = sqlite3_column_text(stmt, 0);
    system(cmd);
}
`
	flows := Analyze(code, "/app/db_handler.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for sqlite3_column_text -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_MySQL_StoredCommandInjection(t *testing.T) {
	code := `
#include <mysql/mysql.h>
#include <cstdlib>

void process(MYSQL *conn) {
    MYSQL_RES *result = mysql_store_result(conn);
    MYSQL_ROW row = mysql_fetch_row(result);
    system(row[0]);
}
`
	flows := Analyze(code, "/app/db_process.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for mysql_fetch_row -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_PQ_StoredCommandInjection(t *testing.T) {
	code := `
#include <libpq-fe.h>
#include <cstdlib>

void process() {
    PGconn *conn = PQconnectdb("dbname=test");
    PGresult *result = PQexec(conn, "SELECT cmd FROM jobs LIMIT 1");
    char *cmd = PQgetvalue(result, 0, 0);
    system(cmd);
}
`
	flows := Analyze(code, "/app/pg_cmd.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for PQgetvalue -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_SQLite3_Blob_CommandInjection(t *testing.T) {
	code := `
#include <sqlite3.h>
#include <cstdlib>

void process(sqlite3 *db) {
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "SELECT cmd FROM uploads LIMIT 1", -1, &stmt, NULL);
    sqlite3_step(stmt);
    auto blob = sqlite3_column_blob(stmt, 0);
    system(blob);
}
`
	flows := Analyze(code, "/app/db_blob.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for sqlite3_column_blob -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// C++ Drogon extended source tests
// =========================================================================

func TestCPP_Drogon_Path_XSS(t *testing.T) {
	code := `
#include <drogon/HttpRequest.h>
#include <drogon/HttpResponse.h>

void handler(const drogon::HttpRequestPtr &req,
             std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
    auto p = req->path();
    auto resp = drogon::HttpResponse::newHttpResponse();
    resp->setBody("<h1>" + p + "</h1>");
    callback(resp);
}
`
	flows := Analyze(code, "/app/drogon_path.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for req->path -> resp->setBody")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Drogon_Body_XSS(t *testing.T) {
	code := `
#include <drogon/HttpRequest.h>
#include <drogon/HttpResponse.h>

void handler(const drogon::HttpRequestPtr &req,
             std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
    auto data = req->body();
    auto resp = drogon::HttpResponse::newHttpResponse();
    resp->setBody("<div>" + std::string(data) + "</div>");
    callback(resp);
}
`
	flows := Analyze(code, "/app/drogon_body.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for req->body -> resp->setBody")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// C++ Oat++ source tests
// =========================================================================

func TestCPP_Oatpp_QueryParam_CommandInjection(t *testing.T) {
	code := `
#include <oatpp/web/protocol/http/incoming/Request.hpp>
#include <cstdlib>

void handler(const std::shared_ptr<oatpp::web::protocol::http::incoming::Request> &request) {
    auto filename = request->getQueryParameter("file");
    std::string cmd = "cat " + filename->std_str();
    system(cmd.c_str());
}
`
	flows := Analyze(code, "/app/oatpp_handler.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for getQueryParameter -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Oatpp_Body_XSS(t *testing.T) {
	code := `
#include <oatpp/web/protocol/http/incoming/Request.hpp>
#include <httplib.h>

void handler(const std::shared_ptr<oatpp::web::protocol::http::incoming::Request> &request,
             httplib::Response &res) {
    auto body = request->readBodyToString();
    res.set_content("<div>" + body->std_str() + "</div>", "text/html");
}
`
	flows := Analyze(code, "/app/oatpp_xss.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for readBodyToString -> res.set_content")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// C++ cpprestsdk source tests
// =========================================================================

func TestCPP_Cpprest_ExtractString_CommandInjection(t *testing.T) {
	code := `
#include <cpprest/http_listener.h>
#include <cstdlib>

void handler(web::http::http_request request) {
    auto body = request.extract_string();
    system(body);
}
`
	flows := Analyze(code, "/app/cpprest_handler.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for request.extract_string -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Cpprest_ExtractJson_XSS(t *testing.T) {
	code := `
#include <cpprest/http_listener.h>
#include <httplib.h>

void handler(web::http::http_request request, httplib::Response &res) {
    auto json = request.extract_json();
    res.set_content("<div>" + json.serialize() + "</div>", "text/html");
}
`
	flows := Analyze(code, "/app/cpprest_xss.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for request.extract_json -> res.set_content")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// C++ safe/sanitized tests
// =========================================================================

// =========================================================================
// C++ XPath injection tests
// =========================================================================

func TestCPP_Libxml2_XPathEval_Injection(t *testing.T) {
	code := `
#include <libxml/xpath.h>
#include <libxml/parser.h>
#include <cstdlib>
#include <string>

void search() {
    char *userQuery = getenv("XPATH_QUERY");
    xmlDocPtr doc = xmlParseFile("data.xml");
    xmlXPathContextPtr ctx = xmlXPathNewContext(doc);
    std::string expr = "//user[@name='" + std::string(userQuery) + "']";
    xmlXPathObjectPtr result = xmlXPathEvalExpression((const xmlChar *)expr.c_str(), ctx);
}
`
	flows := Analyze(code, "/app/xpath_search.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath injection flow for getenv -> xmlXPathEvalExpression")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Pugixml_SelectNodes_Injection(t *testing.T) {
	code := `
#include <pugixml.hpp>
#include <cstdlib>
#include <string>

void search() {
    char *input = getenv("SEARCH_TERM");
    pugi::xml_document doc;
    doc.load_file("config.xml");
    std::string query = "//item[@id='" + std::string(input) + "']";
    auto nodes = doc.select_nodes(query.c_str());
}
`
	flows := Analyze(code, "/app/pugixml_search.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath injection flow for getenv -> select_nodes")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// C++ eval / code execution tests
// =========================================================================

func TestCPP_LuaCAPI_DoString_Injection(t *testing.T) {
	code := `
#include <lua.h>
#include <lauxlib.h>
#include <cstdlib>

void execute() {
    char *userCode = getenv("LUA_CODE");
    lua_State *L = luaL_newstate();
    luaL_openlibs(L);
    luaL_dostring(L, userCode);
    lua_close(L);
}
`
	flows := Analyze(code, "/app/lua_eval.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for getenv -> luaL_dostring")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Pybind11_Eval_Injection(t *testing.T) {
	code := `
#include <pybind11/embed.h>
#include <cstdlib>
namespace py = pybind11;

void execute() {
    char *expr = getenv("PY_EXPR");
    py::scoped_interpreter guard{};
    py::eval(expr);
}
`
	flows := Analyze(code, "/app/pybind_eval.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for getenv -> py::eval")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Dlsym_UserControlled(t *testing.T) {
	code := `
#include <dlfcn.h>
#include <cstdlib>

void loadPlugin() {
    char *funcName = getenv("PLUGIN_FUNC");
    void *handle = dlopen("plugins.so", RTLD_LAZY);
    void *func = dlsym(handle, funcName);
    ((void(*)())func)();
}
`
	flows := Analyze(code, "/app/plugin_loader.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for getenv -> dlsym")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// C++ redirect tests
// =========================================================================

func TestCPP_Drogon_Redirect_OpenRedirect(t *testing.T) {
	code := `
#include <drogon/HttpResponse.h>
#include <cstdlib>

void handler() {
    char *url = getenv("REDIRECT_URL");
    auto resp = drogon::HttpResponse::newRedirectionResponse(url);
}
`
	flows := Analyze(code, "/app/drogon_redirect.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect flow for getenv -> newRedirectionResponse")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Httplib_Redirect_OpenRedirect(t *testing.T) {
	code := `
#include <httplib.h>
#include <string>

void handler(const httplib::Request &req, httplib::Response &res) {
    auto target = req.get_param_value("redirect_url");
    res.set_redirect(target);
}
`
	flows := Analyze(code, "/app/httplib_redirect.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect flow for req.get_param_value -> res.set_redirect")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// C++ safe/sanitized tests
// =========================================================================

func TestCPP_SQLite3_StoredXSS_Sanitized(t *testing.T) {
	code := `
#include <sqlite3.h>
#include <drogon/HttpResponse.h>
#include <drogon/utils/Utilities.h>

void handler(const drogon::HttpRequestPtr &req,
             std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    sqlite3_open("app.db", &db);
    sqlite3_prepare_v2(db, "SELECT name FROM users WHERE id=1", -1, &stmt, NULL);
    sqlite3_step(stmt);
    const char *name = (const char *)sqlite3_column_text(stmt, 0);
    auto safe = drogon::utils::htmlTranslate(std::string(name));
    auto resp = drogon::HttpResponse::newHttpResponse();
    resp->setBody("<h1>Hello " + safe + "</h1>");
    callback(resp);
}
`
	flows := Analyze(code, "/app/db_safe_handler.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Error("expected NO XSS flow when sqlite3_column_text is sanitized via htmlTranslate")
		}
	}
}
