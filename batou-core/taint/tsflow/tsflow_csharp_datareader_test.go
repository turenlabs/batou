package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// ===========================================================================
// C# ADO.NET DbDataReader typed-getter sources (second-order injection).
//
// These tests exercise the idiomatic ADO.NET read pattern:
//
//     var reader = cmd.ExecuteReader();
//     while (reader.Read()) {
//         var name = reader.GetString(0);   // attacker-controlled stored data
//         ... name flows into a SQL/command/HTML sink ...
//     }
//
// The typed getters (GetString/GetValue/GetFieldValue<T>/...) are bound to the
// conventional receiver names `reader`, `dr`, or `rdr`. Before the matcher
// alias that maps these names to "...datareader" ObjectTypes, none of these
// flows were detected (the legacy csharp.data.datareader entry used a "Get*"
// wildcard MethodName the matcher cannot expand). Each test below produces
// ZERO flows on main prior to this change.
//
// All fixtures construct the connection/command inline (no method parameters)
// so the ONLY possible taint source is the DataReader getter itself — the
// flow cannot be attributed to web-handler parameter auto-tainting.
// ===========================================================================

func TestCSharp_DataReader_GetString_SQL(t *testing.T) {
	code := `
using System;
using System.Data.SqlClient;

public class Repo {
    public void Lookup() {
        var conn = new SqlConnection("Server=db;Database=app");
        var cmd1 = new SqlCommand("SELECT username FROM profiles WHERE id = 1", conn);
        var reader = cmd1.ExecuteReader();
        var username = reader.GetString(0);
        var cmd2 = new SqlCommand("SELECT * FROM orders WHERE customer = '" + username + "'", conn);
        cmd2.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/Repo.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow: reader.GetString -> SqlCommand (second-order injection)")
		for _, f := range flows {
			t.Logf("  flow: %s(%s) -> %s (conf: %.2f)", f.Source.Category, f.Source.ID, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_DataReader_GetValue_SQL(t *testing.T) {
	code := `
using System;
using System.Data.SqlClient;

public class Repo {
    public void Lookup() {
        var conn = new SqlConnection("Server=db;Database=app");
        var cmd1 = new SqlCommand("SELECT data FROM kv WHERE id = 1", conn);
        var dr = cmd1.ExecuteReader();
        var data = dr.GetValue(0);
        var cmd2 = new SqlCommand("SELECT * FROM audit WHERE note = '" + data + "'", conn);
        cmd2.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/Repo.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow: dr.GetValue -> SqlCommand (second-order injection)")
	}
}

func TestCSharp_DataReader_GetFieldValue_SQL(t *testing.T) {
	code := `
using System;
using System.Data.SqlClient;

public class Repo {
    public void Lookup() {
        var conn = new SqlConnection("Server=db;Database=app");
        var cmd1 = new SqlCommand("SELECT name FROM users WHERE id = 1", conn);
        var rdr = cmd1.ExecuteReader();
        var name = rdr.GetFieldValue<string>(0);
        var cmd2 = new SqlCommand("SELECT * FROM logs WHERE who = '" + name + "'", conn);
        cmd2.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/Repo.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow: rdr.GetFieldValue<string> -> SqlCommand (second-order injection)")
	}
}

func TestCSharp_DataReader_GetFieldValueAsync_SQL(t *testing.T) {
	code := `
using System;
using System.Data.SqlClient;

public class Repo {
    public async void Lookup() {
        var conn = new SqlConnection("Server=db;Database=app");
        var cmd1 = new SqlCommand("SELECT name FROM users WHERE id = 1", conn);
        var reader = cmd1.ExecuteReader();
        var name = await reader.GetFieldValueAsync<string>(0);
        var cmd2 = new SqlCommand("SELECT * FROM logs WHERE who = '" + name + "'", conn);
        cmd2.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/Repo.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow: reader.GetFieldValueAsync<string> -> SqlCommand (second-order injection)")
	}
}

func TestCSharp_DataReader_GetTextReader_SQL(t *testing.T) {
	code := `
using System;
using System.Data.SqlClient;

public class Repo {
    public void Lookup() {
        var conn = new SqlConnection("Server=db;Database=app");
        var cmd1 = new SqlCommand("SELECT body FROM docs WHERE id = 1", conn);
        var reader = cmd1.ExecuteReader();
        var body = reader.GetTextReader(0);
        var cmd2 = new SqlCommand("SELECT * FROM refs WHERE txt = '" + body + "'", conn);
        cmd2.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/Repo.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow: reader.GetTextReader -> SqlCommand (second-order injection)")
	}
}

func TestCSharp_DataReader_GetSqlString_SQL(t *testing.T) {
	code := `
using System;
using System.Data.SqlClient;

public class Repo {
    public void Lookup() {
        var conn = new SqlConnection("Server=db;Database=app");
        var cmd1 = new SqlCommand("SELECT label FROM tags WHERE id = 1", conn);
        var reader = cmd1.ExecuteReader();
        var label = reader.GetSqlString(0);
        var cmd2 = new SqlCommand("SELECT * FROM items WHERE tag = '" + label + "'", conn);
        cmd2.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/Repo.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow: reader.GetSqlString -> SqlCommand (second-order injection)")
	}
}

func TestCSharp_DataReader_GetSqlValue_SQL(t *testing.T) {
	code := `
using System;
using System.Data.SqlClient;

public class Repo {
    public void Lookup() {
        var conn = new SqlConnection("Server=db;Database=app");
        var cmd1 = new SqlCommand("SELECT v FROM kv WHERE id = 1", conn);
        var reader = cmd1.ExecuteReader();
        var v = reader.GetSqlValue(0);
        var cmd2 = new SqlCommand("SELECT * FROM kv2 WHERE v = '" + v + "'", conn);
        cmd2.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/Repo.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow: reader.GetSqlValue -> SqlCommand (second-order injection)")
	}
}

func TestCSharp_DataReader_GetProviderSpecificValue_SQL(t *testing.T) {
	code := `
using System;
using System.Data.SqlClient;

public class Repo {
    public void Lookup() {
        var conn = new SqlConnection("Server=db;Database=app");
        var cmd1 = new SqlCommand("SELECT v FROM kv WHERE id = 1", conn);
        var reader = cmd1.ExecuteReader();
        var v = reader.GetProviderSpecificValue(0);
        var cmd2 = new SqlCommand("SELECT * FROM kv2 WHERE v = '" + v + "'", conn);
        cmd2.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/Repo.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow: reader.GetProviderSpecificValue -> SqlCommand (second-order injection)")
	}
}

// Realistic provider type (NpgsqlDataReader) with a while(reader.Read()) loop
// and a flow into a command-injection sink rather than SQL — exercises both
// the DbDataReader base-class ObjectType matching and cross-sink generality.
func TestCSharp_DataReader_NpgsqlLoop_Command(t *testing.T) {
	code := `
using System;
using System.Diagnostics;
using Npgsql;

public class Repo {
    public void Run() {
        var conn = new NpgsqlConnection("Host=db;Database=app");
        var cmd1 = new NpgsqlCommand("SELECT host FROM nodes", conn);
        var reader = cmd1.ExecuteReader();
        while (reader.Read()) {
            var host = reader.GetString(0);
            Process.Start("/bin/ping", host);
        }
    }
}
`
	flows := Analyze(code, "/app/Repo.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command flow: reader.GetString -> Process.Start (second-order command injection)")
		for _, f := range flows {
			t.Logf("  flow: %s(%s) -> %s (conf: %.2f)", f.Source.Category, f.Source.ID, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative: a literal/constant column value substitute must NOT produce a flow.
func TestCSharp_DataReader_Negative_Literal(t *testing.T) {
	code := `
using System;
using System.Data.SqlClient;

public class Repo {
    public void Lookup() {
        var conn = new SqlConnection("Server=db;Database=app");
        var username = "static_admin";
        var cmd2 = new SqlCommand("SELECT * FROM orders WHERE customer = '" + username + "'", conn);
        cmd2.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/Repo.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NO SQL flow when the value is a constant (no DataReader read)")
	}
}
