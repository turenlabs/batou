package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// C++ second-order DB-read sources (SrcDatabase)
//
//   - MySQL Connector/C++ (also MariaDB Connector/C++) — sql::ResultSet
//     column readers (getString / getInt / getInt64 / getUInt / getUInt64 /
//     getDouble). The values come back from MySQL; if an earlier write path
//     stored attacker-controlled data they re-enter the program tainted.
//     Pairs with the existing cpp.mysql.connector.statement.* SQL-injection
//     sinks in cpp_sinks.go.
//   - mongocxx (official MongoDB C++ driver) — find_one and the
//     find_one_and_* atomic mutators return the matched BSON document. The
//     document fields hold data stored in MongoDB. These coexist with the
//     existing cpp.mongocxx.* NoSQL-injection sinks (which fire on a tainted
//     *filter*); here the *return value* is tainted.
//
// All fixtures are wrapped in plain functions with no parameters so the
// tsflow web-handler heuristic (which would auto-taint parameters) cannot
// introduce taint — the new source entry is the only taint origin.
// =========================================================================

// ── MySQL Connector/C++ ResultSet ────────────────────────────────────────

func TestCPP_MySQLConnector_ResultSet_GetString_SecondOrderSQLi(t *testing.T) {
	code := `
#include <cppconn/driver.h>
#include <cppconn/statement.h>
#include <cppconn/resultset.h>
#include <string>

void auditNames() {
    sql::Driver *driver = get_driver_instance();
    sql::Connection *conn = driver->connect("tcp://127.0.0.1:3306/db", "u", "p");
    sql::Statement *stmt = conn->createStatement();
    sql::ResultSet *res = stmt->executeQuery("SELECT name FROM users");
    while (res->next()) {
        std::string name = res->getString("name");
        std::string q = "INSERT INTO audit (who) VALUES ('" + name + "')";
        stmt->execute(q);
    }
}
`
	flows := Analyze(code, "/app/mysqlcc_resultset_getstring.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection flow: ResultSet::getString -> Statement::execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_MySQLConnector_ResultSet_GetInt_SecondOrderSQLi(t *testing.T) {
	code := `
#include <cppconn/driver.h>
#include <cppconn/statement.h>
#include <cppconn/resultset.h>
#include <string>

void copyRow() {
    sql::Driver *driver = get_driver_instance();
    sql::Connection *conn = driver->connect("tcp://127.0.0.1:3306/db", "u", "p");
    sql::Statement *stmt = conn->createStatement();
    sql::ResultSet *res = stmt->executeQuery("SELECT id FROM users");
    while (res->next()) {
        int id = res->getInt("id");
        std::string q = "DELETE FROM users WHERE id = " + std::to_string(id);
        stmt->execute(q);
    }
}
`
	flows := Analyze(code, "/app/mysqlcc_resultset_getint.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection flow: ResultSet::getInt -> Statement::execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_MySQLConnector_ResultSet_GetInt64_SecondOrderSQLi(t *testing.T) {
	code := `
#include <cppconn/driver.h>
#include <cppconn/statement.h>
#include <cppconn/resultset.h>
#include <string>

void mirror() {
    sql::Driver *driver = get_driver_instance();
    sql::Connection *conn = driver->connect("tcp://127.0.0.1:3306/db", "u", "p");
    sql::Statement *stmt = conn->createStatement();
    sql::ResultSet *res = stmt->executeQuery("SELECT bigid FROM rows");
    while (res->next()) {
        long long v = res->getInt64("bigid");
        std::string q = "UPDATE rows SET n = " + std::to_string(v) + " WHERE n = 1";
        stmt->execute(q);
    }
}
`
	flows := Analyze(code, "/app/mysqlcc_resultset_getint64.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection flow: ResultSet::getInt64 -> Statement::execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_MySQLConnector_ResultSet_GetUInt_SecondOrderSQLi(t *testing.T) {
	code := `
#include <cppconn/driver.h>
#include <cppconn/statement.h>
#include <cppconn/resultset.h>
#include <string>

void copyCount() {
    sql::Driver *driver = get_driver_instance();
    sql::Connection *conn = driver->connect("tcp://127.0.0.1:3306/db", "u", "p");
    sql::Statement *stmt = conn->createStatement();
    sql::ResultSet *res = stmt->executeQuery("SELECT cnt FROM stats");
    while (res->next()) {
        unsigned int c = res->getUInt("cnt");
        std::string q = "UPDATE stats SET total = " + std::to_string(c);
        stmt->execute(q);
    }
}
`
	flows := Analyze(code, "/app/mysqlcc_resultset_getuint.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection flow: ResultSet::getUInt -> Statement::execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_MySQLConnector_ResultSet_GetUInt64_SecondOrderSQLi(t *testing.T) {
	code := `
#include <cppconn/driver.h>
#include <cppconn/statement.h>
#include <cppconn/resultset.h>
#include <string>

void copyBig() {
    sql::Driver *driver = get_driver_instance();
    sql::Connection *conn = driver->connect("tcp://127.0.0.1:3306/db", "u", "p");
    sql::Statement *stmt = conn->createStatement();
    sql::ResultSet *res = stmt->executeQuery("SELECT bytes FROM files");
    while (res->next()) {
        unsigned long long n = res->getUInt64("bytes");
        std::string q = "UPDATE files SET bytes = " + std::to_string(n) + " WHERE id = 1";
        stmt->execute(q);
    }
}
`
	flows := Analyze(code, "/app/mysqlcc_resultset_getuint64.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection flow: ResultSet::getUInt64 -> Statement::execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_MySQLConnector_ResultSet_GetDouble_SecondOrderSQLi(t *testing.T) {
	code := `
#include <cppconn/driver.h>
#include <cppconn/statement.h>
#include <cppconn/resultset.h>
#include <string>

void copyPrice() {
    sql::Driver *driver = get_driver_instance();
    sql::Connection *conn = driver->connect("tcp://127.0.0.1:3306/db", "u", "p");
    sql::Statement *stmt = conn->createStatement();
    sql::ResultSet *res = stmt->executeQuery("SELECT price FROM items");
    while (res->next()) {
        double p = res->getDouble("price");
        std::string q = "UPDATE items SET price = " + std::to_string(p) + " WHERE id = 1";
        stmt->execute(q);
    }
}
`
	flows := Analyze(code, "/app/mysqlcc_resultset_getdouble.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection flow: ResultSet::getDouble -> Statement::execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// 'result' is a recognised receiver name for sql::ResultSet too.
func TestCPP_MySQLConnector_ResultSet_GetString_ResultReceiver(t *testing.T) {
	code := `
#include <cppconn/driver.h>
#include <cppconn/statement.h>
#include <cppconn/resultset.h>
#include <string>

void run() {
    sql::Driver *driver = get_driver_instance();
    sql::Connection *conn = driver->connect("tcp://127.0.0.1:3306/db", "u", "p");
    sql::Statement *stmt = conn->createStatement();
    sql::ResultSet *result = stmt->executeQuery("SELECT cmd FROM jobs");
    while (result->next()) {
        std::string cmd = result->getString("cmd");
        system(cmd.c_str());
    }
}
`
	flows := Analyze(code, "/app/mysqlcc_resultset_result.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow: ResultSet(result)::getString -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ── mongocxx find_one / find_one_and_* ───────────────────────────────────

func TestCPP_Mongocxx_FindOne_SecondOrderCommand(t *testing.T) {
	code := `
#include <mongocxx/client.hpp>
#include <mongocxx/collection.hpp>
#include <bsoncxx/json.hpp>
#include <bsoncxx/builder/stream/document.hpp>
#include <cstdlib>

void replicate() {
    mongocxx::client client{mongocxx::uri{}};
    mongocxx::database db = client["app"];
    mongocxx::collection coll = db["jobs"];
    auto doc = coll.find_one(bsoncxx::builder::stream::document{} << "active" << true << bsoncxx::builder::stream::finalize);
    std::string j = bsoncxx::to_json(doc->view());
    system(j.c_str());
}
`
	flows := Analyze(code, "/app/mongo_findone_result.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected second-order command flow: mongocxx find_one result -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Mongocxx_FindOneAndUpdate_SecondOrderCommand(t *testing.T) {
	code := `
#include <mongocxx/client.hpp>
#include <bsoncxx/json.hpp>
#include <bsoncxx/builder/stream/document.hpp>
#include <cstdlib>

void rotate() {
    mongocxx::client client{mongocxx::uri{}};
    mongocxx::collection coll = client["app"]["jobs"];
    mongocxx::collection &c = coll;
    auto doc = c.find_one_and_update(
        bsoncxx::builder::stream::document{} << "pending" << true << bsoncxx::builder::stream::finalize,
        bsoncxx::builder::stream::document{} << "$set" << bsoncxx::builder::stream::open_document << "claimed" << true << bsoncxx::builder::stream::close_document << bsoncxx::builder::stream::finalize);
    std::string j = bsoncxx::to_json(doc->view());
    system(j.c_str());
}
`
	flows := Analyze(code, "/app/mongo_fou_result.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected second-order command flow: mongocxx find_one_and_update result -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Mongocxx_FindOneAndReplace_SecondOrderCommand(t *testing.T) {
	code := `
#include <mongocxx/client.hpp>
#include <bsoncxx/json.hpp>
#include <bsoncxx/builder/stream/document.hpp>
#include <cstdlib>

void swap() {
    mongocxx::client client{mongocxx::uri{}};
    mongocxx::collection coll = client["app"]["docs"];
    auto doc = coll.find_one_and_replace(
        bsoncxx::builder::stream::document{} << "k" << "v" << bsoncxx::builder::stream::finalize,
        bsoncxx::builder::stream::document{} << "k" << "v2" << bsoncxx::builder::stream::finalize);
    std::string j = bsoncxx::to_json(doc->view());
    system(j.c_str());
}
`
	flows := Analyze(code, "/app/mongo_for_result.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected second-order command flow: mongocxx find_one_and_replace result -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Mongocxx_FindOneAndDelete_SecondOrderCommand(t *testing.T) {
	code := `
#include <mongocxx/client.hpp>
#include <bsoncxx/json.hpp>
#include <bsoncxx/builder/stream/document.hpp>
#include <cstdlib>

void pop() {
    mongocxx::client client{mongocxx::uri{}};
    mongocxx::collection coll = client["app"]["queue"];
    auto doc = coll.find_one_and_delete(bsoncxx::builder::stream::document{} << "ready" << true << bsoncxx::builder::stream::finalize);
    std::string j = bsoncxx::to_json(doc->view());
    system(j.c_str());
}
`
	flows := Analyze(code, "/app/mongo_fod_result.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected second-order command flow: mongocxx find_one_and_delete result -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ── Negative regression — no source means no flow ────────────────────────

func TestCPP_MySQLConnector_ResultSet_ConstantSQL_NoFlow(t *testing.T) {
	code := `
#include <cppconn/driver.h>
#include <cppconn/statement.h>

void initAudit() {
    sql::Driver *driver = get_driver_instance();
    sql::Connection *conn = driver->connect("tcp://127.0.0.1:3306/db", "u", "p");
    sql::Statement *stmt = conn->createStatement();
    stmt->execute("INSERT INTO audit (who) VALUES ('system')");
}
`
	flows := Analyze(code, "/app/mysqlcc_const.cpp", rules.LangCPP)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did not expect a SQL flow when no DB read feeds the query")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Mongocxx_FindOne_HardcodedResult_NoFlow(t *testing.T) {
	code := `
#include <mongocxx/client.hpp>
#include <bsoncxx/builder/stream/document.hpp>
#include <cstdlib>

void healthcheck() {
    mongocxx::client client{mongocxx::uri{}};
    mongocxx::collection coll = client["app"]["jobs"];
    coll.find_one(bsoncxx::builder::stream::document{} << "active" << true << bsoncxx::builder::stream::finalize);
    system("echo ok");
}
`
	flows := Analyze(code, "/app/mongo_safe.cpp", rules.LangCPP)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("did not expect a command flow when the find_one result is discarded and system() takes a literal")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ── Catalog wiring assertion ─────────────────────────────────────────────

func TestCPP_DBReadSources_Registered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangCPP)
	if cat == nil {
		t.Fatal("C++ catalog not loaded")
	}
	have := map[string]bool{}
	for _, s := range cat.Sources() {
		have[s.ID] = true
	}
	expected := []string{
		"cpp.mysql.connector.resultset.getstring",
		"cpp.mysql.connector.resultset.getint",
		"cpp.mysql.connector.resultset.getint64",
		"cpp.mysql.connector.resultset.getuint",
		"cpp.mysql.connector.resultset.getuint64",
		"cpp.mysql.connector.resultset.getdouble",
		"cpp.mongocxx.find_one.result",
		"cpp.mongocxx.find_one_and_update.result",
		"cpp.mongocxx.find_one_and_replace.result",
		"cpp.mongocxx.find_one_and_delete.result",
	}
	for _, id := range expected {
		if !have[id] {
			t.Errorf("expected source %q to be registered", id)
		}
	}
}
