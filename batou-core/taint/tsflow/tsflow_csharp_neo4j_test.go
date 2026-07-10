package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// C# Neo4j Cypher injection (CWE-943) tests
// Covers: Neo4j.Driver IAsyncSession.RunAsync / IAsyncTransaction.RunAsync /
// IDriver.ExecutableQuery, plus Neo4jClient .Cypher.Match / .Cypher.Where.
// =========================================================================

func TestCSharp_Neo4j_Session_RunAsync_Tainted(t *testing.T) {
	code := `
using System;
using Neo4j.Driver;

public class Handler {
    public async void Handle(IAsyncSession session) {
        string userName = Console.ReadLine();
        string cypher = "MATCH (u:User { name: '" + userName + "' }) RETURN u";
        var cursor = await session.RunAsync(cypher);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Cypher injection flow for Console.ReadLine -> session.RunAsync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Neo4j_Session_Run_Tainted(t *testing.T) {
	code := `
using System;
using Neo4j.Driver;

public class Handler {
    public void Handle(ISession session) {
        string userId = Console.ReadLine();
        string cypher = "MATCH (u:User) WHERE u.id = '" + userId + "' RETURN u";
        var result = session.Run(cypher);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Cypher injection flow for Console.ReadLine -> session.Run (sync)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Neo4j_Tx_RunAsync_Tainted(t *testing.T) {
	code := `
using System;
using Neo4j.Driver;

public class Handler {
    public async void Handle(IAsyncTransaction tx) {
        string label = Console.ReadLine();
        string cypher = "MATCH (n:" + label + ") RETURN n";
        var cursor = await tx.RunAsync(cypher);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Cypher injection flow for Console.ReadLine -> tx.RunAsync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Neo4j_Driver_ExecutableQuery_Tainted(t *testing.T) {
	code := `
using System;
using Neo4j.Driver;

public class Handler {
    public async void Handle(IDriver driver) {
        string filter = Console.ReadLine();
        string cypher = "MATCH (n:User) WHERE n.email CONTAINS '" + filter + "' RETURN n";
        var result = await driver.ExecutableQuery(cypher).ExecuteAsync();
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Cypher injection flow for Console.ReadLine -> driver.ExecutableQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Neo4jClient_Cypher_Match_Tainted(t *testing.T) {
	// Single-line chain: tsflow's multi-line chained-call taint propagation
	// for C# has limitations, so the test uses a single-line form.
	code := `
using System;
using Neo4jClient;

public class Handler {
    public void Handle(IGraphClient _graphClient) {
        string label = Console.ReadLine();
        var users = _graphClient.Cypher.Match("(u:" + label + ")").Return(u => u.As<object>()).Results;
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Cypher injection flow for Console.ReadLine -> _graphClient.Cypher.Match")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Neo4jClient_Cypher_Where_Tainted(t *testing.T) {
	code := `
using System;
using Neo4jClient;

public class Handler {
    public void Handle(IGraphClient _graphClient) {
        string name = Console.ReadLine();
        var users = _graphClient.Cypher.Match("(u:User)").Where("u.name = '" + name + "'").Return(u => u.As<object>()).Results;
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Cypher injection flow for Console.ReadLine -> _graphClient.Cypher.Where")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative: parameterised RunAsync with a hard-coded Cypher string and
// a parameters dictionary should not produce a Cypher injection finding.
func TestCSharp_Neo4j_Session_RunAsync_Parameterised_Safe(t *testing.T) {
	code := `
using System;
using System.Collections.Generic;
using Neo4j.Driver;

public class Handler {
    public async void Handle(IAsyncSession session) {
        string userName = Console.ReadLine();
        var parameters = new Dictionary<string, object> { { "name", userName } };
        var cursor = await session.RunAsync("MATCH (u:User { name: $name }) RETURN u", parameters);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Confidence > 0.7 {
			t.Error("did not expect Cypher injection flow for parameterised session.RunAsync with constant Cypher")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative: Neo4jClient .Cypher.Match with a constant pattern and .WithParam binding
// should not produce a Cypher injection finding.
func TestCSharp_Neo4jClient_Cypher_WithParam_Safe(t *testing.T) {
	code := `
using System;
using Neo4jClient;

public class Handler {
    public void Handle(IGraphClient _graphClient) {
        string name = Console.ReadLine();
        var users = _graphClient.Cypher
            .Match("(u:User)")
            .Where("u.name = $name")
            .WithParam("name", name)
            .Return(u => u.As<object>())
            .Results;
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Confidence > 0.7 {
			t.Error("did not expect Cypher injection flow for Neo4jClient with constant pattern + WithParam binding")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
