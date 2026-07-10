package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// C# DataStax Cassandra CQL injection (CWE-943) tests
// Covers: ISession.Execute(string), ISession.Prepare(string),
// ISession.PrepareAsync(string), and new SimpleStatement(string).
// Reference: https://docs.datastax.com/en/latest-csharp-driver-api/api/Cassandra.ISession.html
// =========================================================================

func TestCSharp_Cassandra_Session_Execute_Tainted(t *testing.T) {
	code := `
using System;
using Cassandra;

public class Handler {
    public void Handle(ISession session) {
        string userId = Console.ReadLine();
        string cql = "SELECT * FROM users WHERE id = '" + userId + "'";
        var rs = session.Execute(cql);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkNoSQL && f.Sink.ID == "csharp.cassandra.session.execute" {
			found = true
		}
	}
	if !found {
		t.Error("expected CQL injection flow for Console.ReadLine -> session.Execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCSharp_Cassandra_Session_Prepare_Tainted(t *testing.T) {
	code := `
using System;
using Cassandra;

public class Handler {
    public void Handle(ISession session) {
        string table = Console.ReadLine();
        string cql = "SELECT * FROM " + table + " WHERE id = ?";
        var prepared = session.Prepare(cql);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkNoSQL && f.Sink.ID == "csharp.cassandra.session.prepare" {
			found = true
		}
	}
	if !found {
		t.Error("expected CQL injection flow for Console.ReadLine -> session.Prepare")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCSharp_Cassandra_Session_PrepareAsync_Tainted(t *testing.T) {
	code := `
using System;
using System.Threading.Tasks;
using Cassandra;

public class Handler {
    public async Task Handle(ISession session) {
        string column = Console.ReadLine();
        string cql = "SELECT " + column + " FROM users WHERE id = ?";
        var prepared = await session.PrepareAsync(cql);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkNoSQL && f.Sink.ID == "csharp.cassandra.session.prepareasync" {
			found = true
		}
	}
	if !found {
		t.Error("expected CQL injection flow for Console.ReadLine -> session.PrepareAsync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCSharp_Cassandra_SimpleStatement_Ctor_Tainted(t *testing.T) {
	code := `
using System;
using Cassandra;

public class Handler {
    public void Handle(ISession session) {
        string filter = Console.ReadLine();
        var stmt = new SimpleStatement("SELECT * FROM posts WHERE body LIKE '%" + filter + "%'");
        var rs = session.Execute(stmt);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkNoSQL && f.Sink.ID == "csharp.cassandra.simplestatement.ctor" {
			found = true
		}
	}
	if !found {
		t.Error("expected CQL injection flow for Console.ReadLine -> new SimpleStatement(...)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

// Negative: parameterised SimpleStatement with a constant CQL and bound values
// (passed via the params object[] argument and ? placeholders) should NOT
// produce a CQL injection finding.
func TestCSharp_Cassandra_SimpleStatement_Parameterised_Safe(t *testing.T) {
	code := `
using System;
using Cassandra;

public class Handler {
    public void Handle(ISession session) {
        string userId = Console.ReadLine();
        var stmt = new SimpleStatement("SELECT * FROM users WHERE id = ?", userId);
        var rs = session.Execute(stmt);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.ID == "csharp.cassandra.simplestatement.ctor" && f.Confidence > 0.7 {
			t.Errorf("did not expect CQL injection finding for SimpleStatement with constant CQL + bound params: %+v", f)
		}
	}
}
