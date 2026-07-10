package tsflow

import (
	"testing"

	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"

	"github.com/turenlabs/batou-core/taint"
)

// =========================================================================
// C# ClickHouse OLAP database SQL injection (CWE-89) tests
//
// Covers two .NET drivers via distinctive entry points:
//   - DarkWanderer/ClickHouse.Client — connection extension methods
//     (ExecuteStatementAsync, ExecuteDataTable)
//   - killwort/ClickHouse.Ado — new ClickHouseCommand(sql, ...)
//
// Refs:
//   https://github.com/DarkWanderer/ClickHouse.Client (ConnectionExtensions.cs)
//   https://github.com/killwort/ClickHouse-Net
// =========================================================================

func TestCSharp_ClickHouse_Connection_ExecuteStatementAsync_Tainted(t *testing.T) {
	code := `
using System;
using System.Threading.Tasks;
using ClickHouse.Client.ADO;
using ClickHouse.Client.Utility;

public class Handler {
    public async Task Handle(ClickHouseConnection conn) {
        string table = Console.ReadLine();
        string sql = "DROP TABLE " + table;
        await conn.ExecuteStatementAsync(sql);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Sink.ID == "csharp.clickhouse.connection.executestatement" {
			found = true
		}
	}
	if !found {
		t.Error("expected SQL injection flow for Console.ReadLine -> conn.ExecuteStatementAsync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCSharp_ClickHouse_Connection_ExecuteDataTable_Tainted(t *testing.T) {
	code := `
using System;
using System.Data;
using ClickHouse.Client.ADO;
using ClickHouse.Client.Utility;

public class Handler {
    public DataTable Handle(ClickHouseConnection conn) {
        string filter = Console.ReadLine();
        string sql = "SELECT * FROM events WHERE host = '" + filter + "'";
        return conn.ExecuteDataTable(sql);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Sink.ID == "csharp.clickhouse.connection.executedatatable" {
			found = true
		}
	}
	if !found {
		t.Error("expected SQL injection flow for Console.ReadLine -> conn.ExecuteDataTable")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCSharp_ClickHouse_Command_Ctor_Tainted(t *testing.T) {
	// ClickHouse.Ado new ClickHouseCommand(string, ClickHouseConnection) ctor
	// — legacy driver, still in production codebases.
	code := `
using System;
using ClickHouse.Ado;

public class Handler {
    public void Handle(ClickHouseConnection connection) {
        string column = Console.ReadLine();
        string sql = "SELECT " + column + " FROM events";
        var cmd = new ClickHouseCommand(sql, connection);
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Sink.ID == "csharp.clickhouse.command.ctor" {
			found = true
		}
	}
	if !found {
		t.Error("expected SQL injection flow for Console.ReadLine -> new ClickHouseCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

// Negative test: constant SQL with parameter binding via cmd.AddParameter(...)
// must NOT produce a ClickHouse SQL-injection finding. This guards against
// the patterns being overly broad (e.g. firing on any .ExecuteStatementAsync
// call regardless of taint).
func TestCSharp_ClickHouse_Connection_ExecuteStatementAsync_Constant_NoFlow(t *testing.T) {
	code := `
using System.Threading.Tasks;
using ClickHouse.Client.ADO;
using ClickHouse.Client.Utility;

public class Handler {
    public async Task Handle(ClickHouseConnection conn) {
        await conn.ExecuteStatementAsync("OPTIMIZE TABLE events FINAL");
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.ID == "csharp.clickhouse.connection.executestatement" {
			t.Errorf("unexpected ClickHouse SQL injection flow on constant SQL: %s -> %s", f.Source.Category, f.Sink.ID)
		}
	}
}
