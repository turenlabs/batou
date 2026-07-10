package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// C++ clickhouse-cpp SQL injection tests (CWE-89)
// The official ClickHouse C++ client (github.com/ClickHouse/clickhouse-cpp)
// has no parameterized-query API for non-INSERT statements. The query
// arrives as a std::string (or a clickhouse::Query wrapping one) on
// Client::Execute / Select / SelectCancelable / SelectWithExternalData /
// BeginInsert. Concatenating tainted input into that string is SQLi.
// =========================================================================

func TestCPP_ClickHouse_ClientExecute_Injection(t *testing.T) {
	code := `
#include <clickhouse/client.h>
#include <string>

void run(const char* argv[]) {
    clickhouse::Client client(clickhouse::ClientOptions().SetHost("localhost"));
    std::string user = argv[1];
    std::string q = "INSERT INTO audit (note) VALUES ('" + user + "')";
    client.Execute(q);
}
`
	flows := Analyze(code, "/app/ch_execute.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for argv -> client.Execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_ClickHouse_ClientSelect_Injection(t *testing.T) {
	code := `
#include <clickhouse/client.h>
#include <string>

void lookup(const char* argv[]) {
    clickhouse::Client client(clickhouse::ClientOptions().SetHost("localhost"));
    std::string name = argv[1];
    std::string q = "SELECT id FROM users WHERE name = '" + name + "'";
    client.Select(q, [](const clickhouse::Block&) {});
}
`
	flows := Analyze(code, "/app/ch_select.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for argv -> client.Select")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_ClickHouse_ClientSelectCancelable_Injection(t *testing.T) {
	code := `
#include <clickhouse/client.h>
#include <string>

void lookup(const char* argv[]) {
    clickhouse::Client client(clickhouse::ClientOptions().SetHost("localhost"));
    std::string col = argv[1];
    std::string q = "SELECT " + col + " FROM big_table";
    client.SelectCancelable(q, [](const clickhouse::Block&) { return true; });
}
`
	flows := Analyze(code, "/app/ch_selcancel.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for argv -> client.SelectCancelable")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_ClickHouse_ClientSelectWithExternalData_Injection(t *testing.T) {
	code := `
#include <clickhouse/client.h>
#include <string>

void lookup(const char* argv[]) {
    clickhouse::Client client(clickhouse::ClientOptions().SetHost("localhost"));
    clickhouse::ExternalTables tables;
    std::string filter = argv[1];
    std::string q = "SELECT * FROM events WHERE region = '" + filter + "'";
    client.SelectWithExternalData(q, tables, [](const clickhouse::Block&) {});
}
`
	flows := Analyze(code, "/app/ch_selext.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for argv -> client.SelectWithExternalData")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_ClickHouse_ClientBeginInsert_Injection(t *testing.T) {
	code := `
#include <clickhouse/client.h>
#include <string>

void run(const char* argv[]) {
    clickhouse::Client client(clickhouse::ClientOptions().SetHost("localhost"));
    std::string table = argv[1];
    std::string q = "INSERT INTO " + table + " VALUES (?)";
    client.BeginInsert(q);
}
`
	flows := Analyze(code, "/app/ch_begininsert.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for argv -> client.BeginInsert")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_ClickHouse_QueryCtor_Injection(t *testing.T) {
	code := `
#include <clickhouse/client.h>
#include <string>

void run(const char* argv[]) {
    clickhouse::Client client(clickhouse::ClientOptions().SetHost("localhost"));
    std::string id = argv[1];
    std::string s = "SELECT * FROM events WHERE id = " + id;
    auto q = clickhouse::Query(s);
    client.Execute(q);
}
`
	flows := Analyze(code, "/app/ch_queryctor.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for argv -> clickhouse::Query ctor")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Safe pattern: typed Block insert (no string concatenation into SQL).
// Client::Insert(table, Block) is the only structurally safe path.
// =========================================================================

func TestCPP_ClickHouse_BlockInsert_Safe(t *testing.T) {
	code := `
#include <clickhouse/client.h>
#include <string>

void run(const char* argv[]) {
    clickhouse::Client client(clickhouse::ClientOptions().SetHost("localhost"));
    std::string user = argv[1];
    auto col = std::make_shared<clickhouse::ColumnString>();
    col->Append(user);
    clickhouse::Block block;
    block.AppendColumn("note", col);
    client.Insert("audit", block);
}
`
	flows := Analyze(code, "/app/ch_blockinsert.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("expected NO SQL injection flow for typed Block insert; got %s -> %s (conf: %.2f)",
				f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
