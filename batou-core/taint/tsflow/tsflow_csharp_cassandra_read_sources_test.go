package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// ===========================================================================
// C# DataStax CassandraCSharpDriver second-order read sources.
//
// Rows read back from Cassandra carry taint from whatever earlier write stored
// them. ISession.Execute / ExecuteAsync return a RowSet of stored rows, and
// Row.GetValue<T>(name|index) extracts a stored column value. Wiring those
// reads into a downstream CQL-injection sink (csharp.cassandra.session.execute)
// or an SSRF sink (HttpClient.GetAsync) demonstrates end-to-end second-order
// injection — the same pattern the existing C# Redis read-source tests prove.
// Reference: https://docs.datastax.com/en/latest-csharp-driver-api/api/Cassandra.Row.html
// ===========================================================================

// Row.GetValue<T>(name) -> session.Execute (second-order CQL injection).
func TestCSharp_Source_Cassandra_RowGetValue_ToExecute(t *testing.T) {
	code := `
using Cassandra;

public class Repo {
    public void Handle(ISession session, Row row) {
        string host = row.GetValue<string>("host");
        session.Execute("SELECT * FROM logs WHERE h = '" + host + "'");
    }
}
`
	flows := Analyze(code, "/app/Repo.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected SnkNoSQL flow for row.GetValue -> session.Execute")
	}
}

// Row.GetValue<T>(index) — the positional-index overload — flows into
// session.Execute (second-order CQL injection).
func TestCSharp_Source_Cassandra_RowGetValueIndex_ToExecute(t *testing.T) {
	code := `
using Cassandra;

public class Repo {
    public void Handle(ISession session, Row row) {
        string name = row.GetValue<string>(0);
        session.Execute("UPDATE audit SET who = '" + name + "'");
    }
}
`
	flows := Analyze(code, "/app/Repo.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected SnkNoSQL flow for row.GetValue(index) -> session.Execute")
	}
}

// session.Execute returns a tainted RowSet that flows into a second
// (concatenated) session.Execute — exercises Execute as BOTH source and sink.
func TestCSharp_Source_Cassandra_SessionExecute_RowSet_ToExecute(t *testing.T) {
	code := `
using Cassandra;

public class Repo {
    public void Handle(ISession session) {
        var rs = session.Execute("SELECT host FROM config");
        session.Execute("DELETE FROM logs WHERE h = '" + rs.ToString() + "'");
    }
}
`
	flows := Analyze(code, "/app/Repo.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected SnkNoSQL flow for session.Execute (RowSet) -> session.Execute")
	}
}

// await session.ExecuteAsync returns a tainted RowSet (await is unwrapped).
func TestCSharp_Source_Cassandra_ExecuteAsync_ToExecute(t *testing.T) {
	code := `
using System.Threading.Tasks;
using Cassandra;

public class Repo {
    public async Task Handle(ISession session) {
        var rows = await session.ExecuteAsync("SELECT host FROM config");
        session.Execute("DELETE FROM logs WHERE h = '" + rows.ToString() + "'");
    }
}
`
	flows := Analyze(code, "/app/Repo.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected SnkNoSQL flow for session.ExecuteAsync -> session.Execute")
	}
}

// Realistic foreach idiom: iterate the RowSet and read each row's column.
func TestCSharp_Source_Cassandra_ForeachRowGetValue_ToExecute(t *testing.T) {
	code := `
using Cassandra;

public class Repo {
    public void Handle(ISession session) {
        var rs = session.Execute("SELECT name FROM users");
        foreach (var row in rs) {
            string name = row.GetValue<string>("name");
            session.Execute("UPDATE audit SET who = '" + name + "'");
        }
    }
}
`
	flows := Analyze(code, "/app/Repo.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected SnkNoSQL flow for foreach row.GetValue -> session.Execute")
	}
}

// Negative regression: a constant CQL whose RowSet is never consumed must NOT
// produce a flow, even though session.Execute is now both a source and a sink.
// Guards against ObjectType "Session" over-broadness.
func TestCSharp_Source_Cassandra_NegativeConstantNoFlow(t *testing.T) {
	code := `
using Cassandra;

public class Repo {
    public void Handle(ISession session) {
        session.Execute("SELECT * FROM users WHERE id = 1");
    }
}
`
	flows := Analyze(code, "/app/Repo.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("did not expect SnkNoSQL flow for constant CQL with unused RowSet")
	}
}
