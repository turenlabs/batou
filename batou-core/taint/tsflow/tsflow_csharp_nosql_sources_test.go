package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// ===========================================================================
// C# NoSQL document-database read sources for second-order taint.
//
// A document fetched back out of a document store (MongoDB.Driver, Azure
// Cosmos DB, RavenDB, LiteDB) carries taint from whatever earlier request
// wrote it. Each test wires a new read source through the existing
// csharp.process.start command-execution sink (Process.Start) to demonstrate
// end-to-end second-order command injection — the same shape the existing
// tsflow_csharp_redis_read_sources_test.go uses for StackExchange.Redis.
// ===========================================================================

func TestCSharp_Source_Mongo_FindSync_ToProcessStart(t *testing.T) {
	code := `
using System.Diagnostics;
using MongoDB.Driver;

public class Repo {
    public void Handle(IMongoCollection<MyDoc> collection, FilterDefinition<MyDoc> filter) {
        var cursor = collection.FindSync(filter);
        var data = cursor.ToString();
        Process.Start(data);
    }
}
`
	flows := Analyze(code, "/app/Repo.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for collection.FindSync -> Process.Start")
		for _, f := range flows {
			t.Logf("  flow: src=%s sink=%s conf=%.2f", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCSharp_Source_Cosmos_ReadItemAsync_ToProcessStart(t *testing.T) {
	code := `
using System.Diagnostics;
using System.Threading.Tasks;
using Microsoft.Azure.Cosmos;

public class Repo {
    public async Task Handle(Container container, PartitionKey pk) {
        var resp = await container.ReadItemAsync<MyDoc>("id", pk);
        var doc = resp.Resource;
        Process.Start(doc.ToString());
    }
}
`
	flows := Analyze(code, "/app/Repo.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for container.ReadItemAsync -> Process.Start")
		for _, f := range flows {
			t.Logf("  flow: src=%s sink=%s conf=%.2f", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCSharp_Source_Cosmos_ReadItemStreamAsync_ToProcessStart(t *testing.T) {
	code := `
using System.Diagnostics;
using System.Threading.Tasks;
using Microsoft.Azure.Cosmos;

public class Repo {
    public async Task Handle(Container container, PartitionKey pk) {
        var resp = await container.ReadItemStreamAsync("id", pk);
        Process.Start(resp.ToString());
    }
}
`
	flows := Analyze(code, "/app/Repo.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for container.ReadItemStreamAsync -> Process.Start")
		for _, f := range flows {
			t.Logf("  flow: src=%s sink=%s conf=%.2f", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCSharp_Source_Cosmos_FeedIterator_ReadNextAsync_ToProcessStart(t *testing.T) {
	code := `
using System.Diagnostics;
using System.Threading.Tasks;
using Microsoft.Azure.Cosmos;

public class Repo {
    public async Task Handle(FeedIterator<dynamic> iterator) {
        var page = await iterator.ReadNextAsync();
        Process.Start(page.ToString());
    }
}
`
	flows := Analyze(code, "/app/Repo.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for iterator.ReadNextAsync -> Process.Start")
		for _, f := range flows {
			t.Logf("  flow: src=%s sink=%s conf=%.2f", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCSharp_Source_Cosmos_DocumentClient_ReadDocumentAsync_ToProcessStart(t *testing.T) {
	code := `
using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Microsoft.Azure.Documents.Client;

public class Repo {
    public async Task Handle(DocumentClient client, Uri docUri) {
        var resp = await client.ReadDocumentAsync(docUri);
        var doc = resp.Resource;
        Process.Start(doc.ToString());
    }
}
`
	flows := Analyze(code, "/app/Repo.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for client.ReadDocumentAsync -> Process.Start")
		for _, f := range flows {
			t.Logf("  flow: src=%s sink=%s conf=%.2f", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCSharp_Source_RavenDB_SessionLoad_ToProcessStart(t *testing.T) {
	code := `
using System.Diagnostics;
using Raven.Client.Documents.Session;

public class Repo {
    public void Handle(IDocumentSession session) {
        var doc = session.Load<MyDoc>("docs/1");
        Process.Start(doc.ToString());
    }
}
`
	flows := Analyze(code, "/app/Repo.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for session.Load -> Process.Start")
		for _, f := range flows {
			t.Logf("  flow: src=%s sink=%s conf=%.2f", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCSharp_Source_RavenDB_SessionLoadAsync_ToProcessStart(t *testing.T) {
	code := `
using System.Diagnostics;
using System.Threading.Tasks;
using Raven.Client.Documents.Session;

public class Repo {
    public async Task Handle(IAsyncDocumentSession session) {
        var doc = await session.LoadAsync<MyDoc>("docs/1");
        Process.Start(doc.ToString());
    }
}
`
	flows := Analyze(code, "/app/Repo.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for session.LoadAsync -> Process.Start")
		for _, f := range flows {
			t.Logf("  flow: src=%s sink=%s conf=%.2f", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCSharp_Source_RavenDB_SessionQuery_ToProcessStart(t *testing.T) {
	code := `
using System.Diagnostics;
using System.Linq;
using Raven.Client.Documents.Session;

public class Repo {
    public void Handle(IDocumentSession session) {
        var results = session.Query<MyDoc>();
        Process.Start(results.ToString());
    }
}
`
	flows := Analyze(code, "/app/Repo.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for session.Query -> Process.Start")
		for _, f := range flows {
			t.Logf("  flow: src=%s sink=%s conf=%.2f", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCSharp_Source_RavenDB_DocumentQuery_ToProcessStart(t *testing.T) {
	code := `
using System.Diagnostics;
using Raven.Client.Documents.Session;

public class Repo {
    public void Handle(IDocumentSession session) {
        var q = session.Advanced.DocumentQuery<MyDoc>();
        Process.Start(q.ToString());
    }
}
`
	flows := Analyze(code, "/app/Repo.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for session.Advanced.DocumentQuery -> Process.Start")
		for _, f := range flows {
			t.Logf("  flow: src=%s sink=%s conf=%.2f", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCSharp_Source_LiteDB_FindById_ToProcessStart(t *testing.T) {
	code := `
using System.Diagnostics;
using LiteDB;

public class Repo {
    public void Handle(ILiteCollection<MyDoc> collection) {
        var doc = collection.FindById(1);
        Process.Start(doc.ToString());
    }
}
`
	flows := Analyze(code, "/app/Repo.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for collection.FindById -> Process.Start")
		for _, f := range flows {
			t.Logf("  flow: src=%s sink=%s conf=%.2f", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCSharp_Source_LiteDB_FindOne_ToProcessStart(t *testing.T) {
	code := `
using System.Diagnostics;
using LiteDB;

public class Repo {
    public void Handle(ILiteCollection<MyDoc> collection) {
        var doc = collection.FindOne(x => x.Id > 0);
        Process.Start(doc.ToString());
    }
}
`
	flows := Analyze(code, "/app/Repo.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for collection.FindOne -> Process.Start")
		for _, f := range flows {
			t.Logf("  flow: src=%s sink=%s conf=%.2f", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// Negative: a constant command string with no document-store data flowing
// into it must not produce a command-injection finding, even when a
// document read happens elsewhere in the method.
func TestCSharp_Source_NoSQL_ConstantSink_Safe(t *testing.T) {
	code := `
using System.Diagnostics;
using LiteDB;

public class Repo {
    public void Handle(ILiteCollection<MyDoc> collection) {
        var doc = collection.FindOne(x => x.Id > 0);
        var name = doc.Name;
        Process.Start("/usr/bin/ls");
    }
}
`
	flows := Analyze(code, "/app/Repo.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("did not expect SnkCommand flow for constant Process.Start argument")
		for _, f := range flows {
			t.Logf("  flow: src=%s sink=%s conf=%.2f", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// -------------------------------------------------------------------------
// Catalog wiring assertion — fast feedback if an entry is dropped or renamed.
// -------------------------------------------------------------------------

func TestCSharp_NoSQLSources_Registered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangCSharp)
	if cat == nil {
		t.Fatal("C# catalog not loaded")
	}
	have := map[string]taint.SourceCategory{}
	for _, s := range cat.Sources() {
		have[s.ID] = s.Category
	}
	expected := []string{
		"csharp.mongo.findsync",
		"csharp.cosmos.container.readitemasync",
		"csharp.cosmos.container.readitemstreamasync",
		"csharp.cosmos.feediterator.readnextasync",
		"csharp.cosmos.documentclient.readdocumentasync",
		"csharp.ravendb.session.load",
		"csharp.ravendb.session.query",
		"csharp.ravendb.session.documentquery",
		"csharp.litedb.collection.findbyid",
		"csharp.litedb.collection.findone",
	}
	for _, id := range expected {
		cat, ok := have[id]
		if !ok {
			t.Errorf("expected source %q to be registered", id)
			continue
		}
		if cat != taint.SrcDatabase {
			t.Errorf("source %q: expected category SrcDatabase, got %v", id, cat)
		}
	}
}
