package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// C# Azure Cosmos DB NoSQL injection (CWE-943) tests
// =========================================================================

func TestCSharp_Cosmos_GetItemQueryIterator_Tainted(t *testing.T) {
	code := `
using System;
using Microsoft.Azure.Cosmos;

public class Handler {
    public void Handle(Container container) {
        string userId = Console.ReadLine();
        string sql = "SELECT * FROM c WHERE c.id = '" + userId + "'";
        var iterator = container.GetItemQueryIterator<dynamic>(sql);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for Console.ReadLine -> Container.GetItemQueryIterator")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Cosmos_QueryDefinition_Tainted(t *testing.T) {
	code := `
using System;
using Microsoft.Azure.Cosmos;

public class Handler {
    public void Handle(Container container) {
        string userId = Console.ReadLine();
        var qd = new QueryDefinition($"SELECT * FROM c WHERE c.id = '{userId}'");
        var iterator = container.GetItemQueryIterator<dynamic>(qd);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for Console.ReadLine -> new QueryDefinition")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Cosmos_GetItemQueryStreamIterator_Tainted(t *testing.T) {
	code := `
using System;
using Microsoft.Azure.Cosmos;

public class Handler {
    public void Handle(Container container) {
        string filter = Console.ReadLine();
        string sql = "SELECT * FROM c WHERE c.name = '" + filter + "'";
        var iterator = container.GetItemQueryStreamIterator(sql);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for Console.ReadLine -> Container.GetItemQueryStreamIterator")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Cosmos_CreateDocumentQuery_Tainted(t *testing.T) {
	code := `
using System;
using Microsoft.Azure.Documents.Client;

public class Handler {
    public void Handle(DocumentClient client, Uri collectionUri) {
        string userId = Console.ReadLine();
        string sql = "SELECT * FROM c WHERE c.id = '" + userId + "'";
        var q = client.CreateDocumentQuery<dynamic>(collectionUri, sql);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for Console.ReadLine -> DocumentClient.CreateDocumentQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Safe: QueryDefinition built from a constant SQL string with no tainted
// input flowing in should not produce a NoSQL injection finding.
func TestCSharp_Cosmos_QueryDefinition_Constant_Safe(t *testing.T) {
	code := `
using System;
using Microsoft.Azure.Cosmos;

public class Handler {
    public void Handle(Container container) {
        var qd = new QueryDefinition("SELECT * FROM c");
        var iterator = container.GetItemQueryIterator<dynamic>(qd);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did not expect NoSQL injection flow for constant QueryDefinition")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
