package tsflow

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// MongoDB C# driver (IMongoCollection<T>) NoSQL-injection sinks (CWE-943).
//
// The C# catalog previously modelled only Find/Aggregate/RunCommand for the
// MongoDB driver, leaving the rest of the filter-accepting write/query
// surface unmodelled. These tests cover the added UpdateOne/UpdateMany/
// DeleteOne/DeleteMany/ReplaceOne/FindOneAnd*/CountDocuments/FindAsync sinks.
//
// Mirrors the documented java.mongodb.collection.* approach: ObjectType is
// left empty because IMongoCollection handles are bound to widely varying
// names (collection, _collection, users, …) that no receiver heuristic
// captures. The method names are MongoDB-driver-specific in .NET (EF Core
// uses Update/Remove, not UpdateOne/DeleteOne), so the false-positive rate
// stays low. DangerousArgs[0] is the filter — a tainted BsonDocument / JSON
// filter is operator-injection.
//
// Source convention matches the existing C# tsflow tests
// (tsflow_csharp_elasticsearch_test.go): Console.ReadLine() user input.
// =========================================================================

func TestCSharp_MongoCollection_SinksRegistered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangCSharp)
	if cat == nil {
		t.Fatal("C# catalog not loaded")
	}
	have := map[string]bool{}
	for _, s := range cat.Sinks() {
		have[s.ID] = true
	}
	expected := []string{
		"csharp.mongo.collection.findasync",
		"csharp.mongo.collection.updateone",
		"csharp.mongo.collection.updatemany",
		"csharp.mongo.collection.deleteone",
		"csharp.mongo.collection.deletemany",
		"csharp.mongo.collection.replaceone",
		"csharp.mongo.collection.findoneandupdate",
		"csharp.mongo.collection.findoneanddelete",
		"csharp.mongo.collection.findoneandreplace",
		"csharp.mongo.collection.countdocuments",
	}
	for _, id := range expected {
		if !have[id] {
			t.Errorf("expected sink %q to be registered", id)
		}
	}
}

func TestCSharp_MongoCollection_FilterInjection(t *testing.T) {
	cases := []struct {
		name    string
		wantID  string
		snippet string
	}{
		{"FindAsync", "csharp.mongo.collection.findasync", `var cursor = await collection.FindAsync(input);`},
		{"UpdateOne", "csharp.mongo.collection.updateone", `collection.UpdateOne(input, update);`},
		{"UpdateManyAsync", "csharp.mongo.collection.updatemany", `await collection.UpdateManyAsync(input, update);`},
		{"DeleteOne", "csharp.mongo.collection.deleteone", `collection.DeleteOne(input);`},
		{"DeleteManyAsync", "csharp.mongo.collection.deletemany", `await collection.DeleteManyAsync(input);`},
		{"ReplaceOne", "csharp.mongo.collection.replaceone", `collection.ReplaceOne(input, doc);`},
		{"FindOneAndUpdate", "csharp.mongo.collection.findoneandupdate", `collection.FindOneAndUpdate(input, update);`},
		{"FindOneAndDeleteAsync", "csharp.mongo.collection.findoneanddelete", `await collection.FindOneAndDeleteAsync(input);`},
		{"FindOneAndReplace", "csharp.mongo.collection.findoneandreplace", `collection.FindOneAndReplace(input, doc);`},
		{"CountDocumentsAsync", "csharp.mongo.collection.countdocuments", `await collection.CountDocumentsAsync(input);`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code := `
using System;
using System.Threading.Tasks;
using MongoDB.Driver;

public class Repo {
    public async Task Handle(IMongoCollection<BsonDocument> collection) {
        string input = Console.ReadLine();
        ` + tc.snippet + `
    }
}
`
			flows := Analyze(code, "/app/Repo.cs", rules.LangCSharp)
			if !findFlowByID(flows, tc.wantID) {
				t.Errorf("expected %s flow for snippet %q", tc.wantID, tc.snippet)
				for _, f := range flows {
					t.Logf("  flow: src=%s sink=%s id=%s conf=%.2f", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
				}
			}
		})
	}
}

// Negative control: a hard-coded/literal filter must NOT fire. Catches the
// catastrophic "ObjectType empty + generic method name fires on every call"
// regression — DangerousArgs[0] means only a tainted first argument flags.
func TestCSharp_MongoCollection_HardcodedFilter_NoFlow(t *testing.T) {
	code := `
using System;
using System.Threading.Tasks;
using MongoDB.Driver;

public class Repo {
    public async Task Handle(IMongoCollection<BsonDocument> collection) {
        string input = Console.ReadLine();
        var safeFilter = "{ active: true }";
        await collection.DeleteManyAsync(safeFilter);
    }
}
`
	flows := Analyze(code, "/app/Repo.cs", rules.LangCSharp)
	for _, f := range flows {
		if strings.HasPrefix(f.Sink.ID, "csharp.mongo.collection.") {
			t.Errorf("unexpected MongoDB flow on a hardcoded filter: id=%s", f.Sink.ID)
		}
	}
}
