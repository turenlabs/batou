package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// ===========================================================================
// C# ASP.NET Core cache abstractions as second-order taint sources.
//
// IDistributedCache (Microsoft.Extensions.Caching.Distributed) and IMemoryCache
// (Microsoft.Extensions.Caching.Memory) are the standard .NET caching
// interfaces. A read returns a value stored on an earlier request, which may
// carry user-controlled taint. These tests wire a cache read into a SqlCommand
// (SnkSQLQuery) to demonstrate end-to-end second-order SQL injection.
//
// The cache receiver-name match (`_cache`, `cache`, `distributedCache`,
// `memoryCache`) is provided by the cache case in matcher.go. Without that
// case the idiomatic `_cache` receiver does not prefix-match the interface
// type name and the source never fires — the positive tests below fail before
// the matcher change and pass after it.
// ===========================================================================

func TestCSharp_Source_DistributedCache_GetString_ToSqlCommand(t *testing.T) {
	code := `
using Microsoft.Extensions.Caching.Distributed;
using System.Data.SqlClient;

public class ReportService {
    private readonly IDistributedCache _cache;
    public void Build(SqlConnection conn) {
        string name = _cache.GetString("user:name");
        var cmd = new SqlCommand("SELECT * FROM users WHERE name = '" + name + "'", conn);
    }
}
`
	flows := Analyze(code, "/app/ReportService.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SnkSQLQuery flow for IDistributedCache.GetString -> SqlCommand")
	}
}

func TestCSharp_Source_DistributedCache_GetStringAsync_ToSqlCommand(t *testing.T) {
	code := `
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Distributed;
using System.Data.SqlClient;

public class ReportService {
    private readonly IDistributedCache _cache;
    public async Task Build(SqlConnection conn) {
        string name = await _cache.GetStringAsync("user:name");
        var cmd = new SqlCommand("SELECT * FROM users WHERE name = '" + name + "'", conn);
    }
}
`
	flows := Analyze(code, "/app/ReportService.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SnkSQLQuery flow for IDistributedCache.GetStringAsync -> SqlCommand")
	}
}

func TestCSharp_Source_DistributedCache_Get_ToSqlCommand(t *testing.T) {
	code := `
using Microsoft.Extensions.Caching.Distributed;
using System.Data.SqlClient;

public class ReportService {
    private readonly IDistributedCache cache;
    public void Build(SqlConnection conn) {
        var blob = cache.Get("user:profile");
        var cmd = new SqlCommand("SELECT * FROM users WHERE id = " + blob.ToString(), conn);
    }
}
`
	flows := Analyze(code, "/app/ReportService.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SnkSQLQuery flow for IDistributedCache.Get -> SqlCommand")
	}
}

func TestCSharp_Source_MemoryCache_Get_ToSqlCommand(t *testing.T) {
	code := `
using Microsoft.Extensions.Caching.Memory;
using System.Data.SqlClient;

public class ReportService {
    private readonly IMemoryCache _cache;
    public void Build(SqlConnection conn) {
        var name = _cache.Get("user:name");
        var cmd = new SqlCommand("SELECT * FROM users WHERE name = '" + name.ToString() + "'", conn);
    }
}
`
	flows := Analyze(code, "/app/ReportService.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SnkSQLQuery flow for IMemoryCache.Get -> SqlCommand")
	}
}

func TestCSharp_Source_MemoryCache_GetOrCreate_ToSqlCommand(t *testing.T) {
	code := `
using Microsoft.Extensions.Caching.Memory;
using System.Data.SqlClient;

public class ReportService {
    private readonly IMemoryCache memoryCache;
    public void Build(SqlConnection conn) {
        var name = memoryCache.GetOrCreate("user:name", e => LoadName());
        var cmd = new SqlCommand("SELECT * FROM users WHERE name = '" + name.ToString() + "'", conn);
    }
}
`
	flows := Analyze(code, "/app/ReportService.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SnkSQLQuery flow for IMemoryCache.GetOrCreate -> SqlCommand")
	}
}

func TestCSharp_Source_MemoryCache_GetOrCreateAsync_ToSqlCommand(t *testing.T) {
	code := `
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
using System.Data.SqlClient;

public class ReportService {
    private readonly IMemoryCache _cache;
    public async Task Build(SqlConnection conn) {
        var name = await _cache.GetOrCreateAsync("user:name", e => LoadNameAsync());
        var cmd = new SqlCommand("SELECT * FROM users WHERE name = '" + name.ToString() + "'", conn);
    }
}
`
	flows := Analyze(code, "/app/ReportService.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SnkSQLQuery flow for IMemoryCache.GetOrCreateAsync -> SqlCommand")
	}
}

// Scoping guard: a non-cache receiver calling .GetString() must NOT be treated
// as a cache source. Proves the matcher cache case is gated on cache-like
// receiver names and does not turn GetString into a global source.
func TestCSharp_Source_Cache_NegativeNonCacheReceiver(t *testing.T) {
	code := `
using System.Data.SqlClient;

public class ReportService {
    public void Build(SqlConnection conn) {
        var formatter = new CustomFormatter();
        string s = formatter.GetString("user:name");
        var cmd = new SqlCommand("SELECT * FROM users WHERE name = '" + s + "'", conn);
    }
}
`
	flows := Analyze(code, "/app/ReportService.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did not expect SnkSQLQuery flow for non-cache receiver .GetString()")
	}
}

// Negative regression: a hard-coded constant query must NOT trigger a flow even
// though SqlCommand is a sink and a cache read is present but unused.
func TestCSharp_Source_Cache_NegativeConstantQueryNoFlow(t *testing.T) {
	code := `
using Microsoft.Extensions.Caching.Distributed;
using System.Data.SqlClient;

public class ReportService {
    private readonly IDistributedCache _cache;
    public void Build(SqlConnection conn) {
        var cmd = new SqlCommand("SELECT * FROM users WHERE id = 1", conn);
    }
}
`
	flows := Analyze(code, "/app/ReportService.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did not expect SnkSQLQuery flow for constant query")
	}
}
