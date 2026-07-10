package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// C# Google Cloud Data Warehouse SQL injection (CWE-89) tests
// Covers:
//   - Google.Cloud.BigQuery.V2 BigQueryClient.ExecuteQuery / ExecuteQueryAsync
//   - Google.Cloud.BigQuery.V2 BigQueryClient.CreateQueryJob / CreateQueryJobAsync
//   - Google.Cloud.Spanner.Data SpannerConnection.CreateSelectCommand
//   - Google.Cloud.Spanner.Data SpannerConnection.CreateDmlCommand
//   - Google.Cloud.Spanner.Data new SpannerCommand(sql, connection, ...)
//
// Tests construct the client/connection locally (rather than receiving it as
// a function parameter) to avoid the seedParams web-handler heuristic, which
// otherwise marks parameters as tainted just because the body contains
// substring "Query(" — masking whether the new sink rule is actually firing
// on the dangerous-arg path versus the receiver-tainted fallback.
// =========================================================================

func TestCSharp_BigQuery_Client_ExecuteQuery_Tainted(t *testing.T) {
	code := `
using System;
using Google.Cloud.BigQuery.V2;

public class Handler {
    public void Handle() {
        var bigQueryClient = BigQueryClient.Create("my-project");
        string userId = Console.ReadLine();
        string sql = "SELECT name FROM dataset.users WHERE id = '" + userId + "'";
        var results = bigQueryClient.ExecuteQuery(sql, parameters: null);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Sink.ID == "csharp.bigquery.client.executequery" {
			found = true
		}
	}
	if !found {
		t.Error("expected SQL injection flow for Console.ReadLine -> BigQueryClient.ExecuteQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCSharp_BigQuery_Client_ExecuteQueryAsync_Tainted(t *testing.T) {
	code := `
using System;
using System.Threading.Tasks;
using Google.Cloud.BigQuery.V2;

public class Handler {
    public async Task Handle() {
        var bigQueryClient = await BigQueryClient.CreateAsync("my-project");
        string column = Console.ReadLine();
        string sql = "SELECT " + column + " FROM dataset.events";
        var results = await bigQueryClient.ExecuteQueryAsync(sql, parameters: null);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Sink.ID == "csharp.bigquery.client.executequery" {
			found = true
		}
	}
	if !found {
		t.Error("expected SQL injection flow for Console.ReadLine -> BigQueryClient.ExecuteQueryAsync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCSharp_BigQuery_Client_CreateQueryJob_Tainted(t *testing.T) {
	code := `
using System;
using Google.Cloud.BigQuery.V2;

public class Handler {
    public void Handle() {
        var bigQueryClient = BigQueryClient.Create("my-project");
        string filter = Console.ReadLine();
        string sql = "SELECT * FROM dataset.logs WHERE message LIKE '%" + filter + "%'";
        var job = bigQueryClient.CreateQueryJob(sql, parameters: null);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Sink.ID == "csharp.bigquery.client.createqueryjob" {
			found = true
		}
	}
	if !found {
		t.Error("expected SQL injection flow for Console.ReadLine -> BigQueryClient.CreateQueryJob")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCSharp_BigQuery_Client_CreateQueryJobAsync_Tainted(t *testing.T) {
	code := `
using System;
using System.Threading.Tasks;
using Google.Cloud.BigQuery.V2;

public class Handler {
    public async Task Handle() {
        var bigQueryClient = await BigQueryClient.CreateAsync("my-project");
        string table = Console.ReadLine();
        string sql = "SELECT * FROM " + table;
        var job = await bigQueryClient.CreateQueryJobAsync(sql, parameters: null);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Sink.ID == "csharp.bigquery.client.createqueryjob" {
			found = true
		}
	}
	if !found {
		t.Error("expected SQL injection flow for Console.ReadLine -> BigQueryClient.CreateQueryJobAsync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

// Negative: BigQuery query with constant SQL and BigQueryParameter[] for
// binding should NOT produce a SQL injection finding (parameters carry the
// user value safely via @name placeholders).
func TestCSharp_BigQuery_Client_Parameterized_Safe(t *testing.T) {
	code := `
using System;
using Google.Cloud.BigQuery.V2;

public class Handler {
    public void Handle() {
        var bigQueryClient = BigQueryClient.Create("my-project");
        string userId = Console.ReadLine();
        var parameters = new[] { new BigQueryParameter("id", BigQueryDbType.String, userId) };
        var results = bigQueryClient.ExecuteQuery("SELECT name FROM dataset.users WHERE id = @id", parameters);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.ID == "csharp.bigquery.client.executequery" && f.Confidence > 0.7 {
			t.Errorf("did not expect SQL injection finding for parameterized BigQuery ExecuteQuery: %+v", f)
		}
	}
}

func TestCSharp_Spanner_Connection_CreateSelectCommand_Tainted(t *testing.T) {
	code := `
using System;
using Google.Cloud.Spanner.Data;

public class Handler {
    public void Handle() {
        var spannerConnection = new SpannerConnection("Data Source=projects/p/instances/i/databases/d");
        string column = Console.ReadLine();
        string sql = "SELECT " + column + " FROM Singers";
        var cmd = spannerConnection.CreateSelectCommand(sql);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Sink.ID == "csharp.spanner.connection.createselectcommand" {
			found = true
		}
	}
	if !found {
		t.Error("expected SQL injection flow for Console.ReadLine -> SpannerConnection.CreateSelectCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCSharp_Spanner_Connection_CreateDmlCommand_Tainted(t *testing.T) {
	code := `
using System;
using Google.Cloud.Spanner.Data;

public class Handler {
    public void Handle() {
        var spannerConnection = new SpannerConnection("Data Source=projects/p/instances/i/databases/d");
        string filter = Console.ReadLine();
        string dml = "UPDATE Singers SET FirstName = '" + filter + "' WHERE SingerId = 1";
        var cmd = spannerConnection.CreateDmlCommand(dml);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Sink.ID == "csharp.spanner.connection.createdmlcommand" {
			found = true
		}
	}
	if !found {
		t.Error("expected SQL injection flow for Console.ReadLine -> SpannerConnection.CreateDmlCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCSharp_Spanner_Command_Ctor_Tainted(t *testing.T) {
	code := `
using System;
using Google.Cloud.Spanner.Data;

public class Handler {
    public void Handle() {
        var spannerConnection = new SpannerConnection("Data Source=projects/p/instances/i/databases/d");
        string artist = Console.ReadLine();
        string sql = "SELECT AlbumId FROM Albums WHERE Artist = '" + artist + "'";
        var cmd = new SpannerCommand(sql, spannerConnection);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Sink.ID == "csharp.spanner.command.ctor" {
			found = true
		}
	}
	if !found {
		t.Error("expected SQL injection flow for Console.ReadLine -> new SpannerCommand(sql, conn)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

// Negative: Spanner CreateSelectCommand with constant SQL + SpannerParameterCollection
// for binding user values should NOT produce a SQL injection finding.
func TestCSharp_Spanner_Connection_Parameterized_Safe(t *testing.T) {
	code := `
using System;
using Google.Cloud.Spanner.Data;

public class Handler {
    public void Handle() {
        var spannerConnection = new SpannerConnection("Data Source=projects/p/instances/i/databases/d");
        string lastName = Console.ReadLine();
        var cmd = spannerConnection.CreateSelectCommand(
            "SELECT FirstName FROM Singers WHERE LastName = @lastName",
            new SpannerParameterCollection { { "lastName", SpannerDbType.String, lastName } });
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.ID == "csharp.spanner.connection.createselectcommand" && f.Confidence > 0.7 {
			t.Errorf("did not expect SQL injection finding for parameterized Spanner CreateSelectCommand: %+v", f)
		}
	}
}
