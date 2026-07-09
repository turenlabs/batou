package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"

	_ "github.com/turenlabs/batou-core/taint/languages"
)

// Load-bearing FP test: a relative URI sent through a NAMED HttpClient
// (CreateClient("...")) cannot change the destination host, so the CWE-918
// SSRF flow is a false positive and must be suppressed. Mirrors bitwarden
// server's SsoController.PreValidate.
func TestCSharp_NamedClient_RelativeURI_SSRF_Suppressed(t *testing.T) {
	code := `
using Microsoft.AspNetCore.Mvc;

[Route("sso/[action]")]
public class SsoController : Controller {
    private readonly IHttpClientFactory _clientFactory;

    [HttpGet]
    public async Task<IActionResult> PreValidate(string domainHint) {
        var culture = "en-US";
        var requestPath = $"/Account/PreValidate?domainHint={domainHint}&culture={culture}";
        var httpClient = _clientFactory.CreateClient("InternalSso");
        using var responseMessage = await httpClient.GetAsync(requestPath);
        return Content("ok");
    }
}
`
	flows := Analyze(code, "/app/SsoController.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected relative-URI named-client GetAsync to NOT flag SSRF (host is pinned by CreateClient BaseAddress)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// TP guard 1: an ABSOLUTE URL built from the tainted param can retarget the
// host — the named-client relative-URI suppression must NOT fire.
func TestCSharp_NamedClient_AbsoluteURL_SSRF_StillFlags(t *testing.T) {
	code := `
using Microsoft.AspNetCore.Mvc;

[Route("sso/[action]")]
public class SsoController : Controller {
    private readonly IHttpClientFactory _clientFactory;

    [HttpGet]
    public async Task<IActionResult> Fetch(string target) {
        var requestUrl = $"https://{target}/data";
        var httpClient = _clientFactory.CreateClient("InternalSso");
        using var responseMessage = await httpClient.GetAsync(requestUrl);
        return Content("ok");
    }
}
`
	flows := Analyze(code, "/app/SsoController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected absolute-URL GetAsync to STILL flag SSRF even through a named client (host is attacker-controlled)")
	}
}

// TP guard 2: an UNNAMED client (new HttpClient()) has no pinned BaseAddress,
// so even a relative-looking path is not host-pinned — must still flag.
func TestCSharp_UnnamedClient_RelativeURI_SSRF_StillFlags(t *testing.T) {
	code := `
using Microsoft.AspNetCore.Mvc;

[Route("sso/[action]")]
public class SsoController : Controller {
    [HttpGet]
    public async Task<IActionResult> Fetch(string path) {
        var requestPath = "/api/" + path;
        var httpClient = new HttpClient();
        using var responseMessage = await httpClient.GetAsync(requestPath);
        return Content("ok");
    }
}
`
	flows := Analyze(code, "/app/SsoController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected unnamed-client (new HttpClient()) GetAsync to STILL flag SSRF (no pinned BaseAddress)")
	}
}
