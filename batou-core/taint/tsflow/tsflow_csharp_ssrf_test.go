package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// C# SSRF sinks for modern HTTP clients (CWE-918)
// Covers Flurl, System.Net.Http.Json, HttpRequestMessage, grpc-dotnet,
// and WebClient upload/OpenRead variants not in the core sink list.
// =========================================================================

func TestCSharp_SSRF_Flurl_GetJsonAsync(t *testing.T) {
	code := `
using System;
using Flurl.Http;

public class Handler {
    public async void Handle() {
        string url = Console.ReadLine();
        var result = await url.GetJsonAsync<object>();
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for Console.ReadLine -> Flurl GetJsonAsync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_SSRF_Flurl_PostJsonAsync(t *testing.T) {
	code := `
using System;
using Flurl.Http;

public class Handler {
    public async void Handle() {
        string url = Console.ReadLine();
        var result = await url.PostJsonAsync(new { name = "test" });
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for Console.ReadLine -> Flurl PostJsonAsync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_SSRF_Flurl_DownloadFileAsync(t *testing.T) {
	code := `
using System;
using Flurl.Http;

public class Handler {
    public async void Handle() {
        string url = Console.ReadLine();
        await url.DownloadFileAsync("/tmp", "file.bin");
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for Console.ReadLine -> Flurl DownloadFileAsync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_SSRF_HttpClient_PostAsJsonAsync(t *testing.T) {
	code := `
using System;
using System.Net.Http;
using System.Net.Http.Json;

public class Handler {
    public async void Handle() {
        string url = Console.ReadLine();
        var client = new HttpClient();
        var result = await client.PostAsJsonAsync(url, new { id = 1 });
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for Console.ReadLine -> HttpClient.PostAsJsonAsync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_SSRF_HttpClient_GetFromJsonAsync(t *testing.T) {
	code := `
using System;
using System.Net.Http;
using System.Net.Http.Json;

public class Handler {
    public async void Handle() {
        string url = Console.ReadLine();
        var client = new HttpClient();
        var result = await client.GetFromJsonAsync<object>(url);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for Console.ReadLine -> HttpClient.GetFromJsonAsync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_SSRF_HttpRequestMessage_Constructor(t *testing.T) {
	code := `
using System;
using System.Net.Http;

public class Handler {
    public async void Handle() {
        string url = Console.ReadLine();
        var req = new HttpRequestMessage(HttpMethod.Get, url);
        var client = new HttpClient();
        await client.SendAsync(req);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for Console.ReadLine -> new HttpRequestMessage(..., url)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_SSRF_GrpcChannel_ForAddress(t *testing.T) {
	code := `
using System;
using Grpc.Net.Client;

public class Handler {
    public void Handle() {
        string addr = Console.ReadLine();
        var channel = GrpcChannel.ForAddress(addr);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for Console.ReadLine -> GrpcChannel.ForAddress")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_SSRF_WebClient_UploadString(t *testing.T) {
	code := `
using System;
using System.Net;

public class Handler {
    public void Handle() {
        string url = Console.ReadLine();
        var client = new WebClient();
        client.UploadString(url, "payload");
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for Console.ReadLine -> WebClient.UploadString")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_SSRF_WebClient_UploadData(t *testing.T) {
	code := `
using System;
using System.Net;

public class Handler {
    public void Handle() {
        string url = Console.ReadLine();
        var client = new WebClient();
        byte[] data = new byte[] { 1, 2, 3 };
        client.UploadData(url, data);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for Console.ReadLine -> WebClient.UploadData")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// WebClient.UploadValues(url, NameValueCollection) is the form-POST sibling of
// UploadString/UploadData — the first argument is the request URL, so a tainted
// URL flowing into it is SSRF (CWE-918). IssueBlot.NET
// NetworkConnectionIdentifierInjection3.cs uses exactly this shape; before the
// csharp.webclient.uploadvalues sink existed it was the only Upload*/Download*
// call on that receiver that produced no flow.
func TestCSharp_SSRF_WebClient_UploadValues(t *testing.T) {
	code := `
using System;
using System.Net;
using System.Collections.Specialized;

public class Handler {
    public void Handle() {
        string url = "http://" + Console.ReadLine();
        using (var client = new WebClient()) {
            var resp = client.UploadValues(url, new NameValueCollection());
        }
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for Console.ReadLine -> WebClient.UploadValues")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// The 3-arg overload UploadValues(url, "POST", coll) still carries the URL in
// arg 0 — must also fire.
func TestCSharp_SSRF_WebClient_UploadValues_PostOverload(t *testing.T) {
	code := `
using System;
using System.Net;
using System.Collections.Specialized;

public class Handler {
    public void Handle() {
        string url = "http://" + Console.ReadLine();
        using (var client = new WebClient()) {
            var resp = client.UploadValues(url, "POST", new NameValueCollection());
        }
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for Console.ReadLine -> WebClient.UploadValues (POST overload)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// NEGATIVE: a constant/literal URL into UploadValues is not SSRF — the URL is
// not attacker-controlled, so the dangerous-arg-0 contract must keep it clean.
func TestCSharp_SSRF_WebClient_UploadValues_ConstURL_NoFlow(t *testing.T) {
	code := `
using System;
using System.Net;
using System.Collections.Specialized;

public class Handler {
    public void Handle() {
        var client = new WebClient();
        var resp = client.UploadValues("https://api.internal/metrics", new NameValueCollection());
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("did not expect SSRF flow for a constant URL into UploadValues")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Receiver-method SSRF on the CORE HttpClient / WebClient sinks. These sinks
// historically carried a fully-qualified ObjectType ("HttpClient",
// "System.Net.WebClient") that no real receiver variable (client/wc/http)
// prefix-matches, so the idiomatic `client.GetAsync(url)` / `wc.DownloadString(url)`
// forms went entirely undetected even though the catalog entry existed
// (dead-mechanism class-2). The receiver-alias block in matchesCatalogEntry
// bridges the conventional HTTP-client receiver names to these ObjectTypes.
// =========================================================================

func TestCSharp_SSRF_HttpClient_GetAsync_Receiver(t *testing.T) {
	code := `
using System;
using System.Net.Http;

public class Handler {
    public void Handle() {
        string url = "http://" + Console.ReadLine();
        var client = new HttpClient();
        var r = client.GetAsync(url).Result;
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for Console.ReadLine -> client.GetAsync(url)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_SSRF_HttpClient_PostAsync_Receiver(t *testing.T) {
	code := `
using System;
using System.Net.Http;

public class Handler {
    public void Handle() {
        string url = "http://" + Console.ReadLine();
        var client = new HttpClient();
        var r = client.PostAsync(url, new StringContent("")).Result;
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for Console.ReadLine -> client.PostAsync(url, ...)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_SSRF_WebClient_DownloadString_Receiver(t *testing.T) {
	code := `
using System;
using System.Net;

public class Handler {
    public void Handle() {
        string url = "http://" + Console.ReadLine();
        var wc = new WebClient();
        var s = wc.DownloadString(url);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for Console.ReadLine -> wc.DownloadString(url)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_SSRF_WebClient_DownloadData_Receiver(t *testing.T) {
	code := `
using System;
using System.Net;

public class Handler {
    public void Handle() {
        string url = "http://" + Console.ReadLine();
        var wc = new WebClient();
        var b = wc.DownloadData(url);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for Console.ReadLine -> wc.DownloadData(url)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_SSRF_HttpClient_FieldReceiver(t *testing.T) {
	// HTTP clients are frequently stored as a field `_httpClient` / `_client`.
	code := `
using System;
using System.Net.Http;

public class Handler {
    private HttpClient _httpClient = new HttpClient();
    public void Handle() {
        string url = "http://" + Console.ReadLine();
        var r = _httpClient.GetStringAsync(url).Result;
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for Console.ReadLine -> _httpClient.GetStringAsync(url)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- NEGATIVE coverage: the receiver alias must not over-fire. ---

// A const/literal URL produces no taint, so no SSRF flow even though the
// receiver+method match the sink.
func TestCSharp_SSRF_HttpClient_ConstURL_NoFlow(t *testing.T) {
	code := `
using System;
using System.Net.Http;

public class Handler {
    public void Handle() {
        var client = new HttpClient();
        var r = client.GetAsync("https://api.example.com/health").Result;
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("did NOT expect an SSRF flow for a constant URL")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// A non-HTTP receiver named `cache` with a same-named GetAsync method (e.g.
// IDistributedCache.GetAsync(key)) must NOT be associated with the HttpClient
// SSRF sink — the alias is scoped to HTTP-client receiver spellings.
func TestCSharp_SSRF_CacheGetAsync_NotSSRF(t *testing.T) {
	code := `
using System;
using Microsoft.Extensions.Caching.Distributed;

public class Handler {
    private IDistributedCache cache;
    public void Handle() {
        string key = Console.ReadLine();
        var bytes = cache.GetAsync(key).Result;
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("did NOT expect an SSRF flow for cache.GetAsync(key)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Generic fix coverage: C# generic method calls (e.g. GetFromJsonAsync<T>)
// must be extracted by method name only. This used to fail because the
// "name" field of member_access_expression returned the full "Foo<T>" text. ---

func TestCSharp_SSRF_GenericMethod_Resolution(t *testing.T) {
	// Regression coverage for csharpConfig.extractCallName generic_name handling.
	// Both calls use generic type arguments that would otherwise break lookup.
	code := `
using System;
using System.Net.Http;
using System.Net.Http.Json;

public class Handler {
    public async void Handle() {
        string url = Console.ReadLine();
        var client = new HttpClient();
        var a = await client.GetFromJsonAsync<object>(url);
        var b = await url.GetJsonAsync<object>();
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	count := 0
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			count++
		}
	}
	if count < 2 {
		t.Errorf("expected at least 2 SSRF flows from generic method calls, got %d", count)
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
