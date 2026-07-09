package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Tests for the additional HTTP-client SSRF sinks (CWE-918) added alongside the
// existing axios/got/undici/http entries:
//
//   - js.axios.client.ssrf  — bare callable form axios(url) / axios(config)
//   - js.axios.head.ssrf    — axios.head(url) (HEAD is a classic SSRF probe)
//   - js.https.get.ssrf     — Node.js https.get(url) (https module, not http)
//   - js.got.method.ssrf    — got.get/post/put/delete/patch/head(url)
//   - js.got.stream.ssrf    — got.stream(url)
//   - js.got.paginate.ssrf  — got.paginate(url)
//   - js.superagent.method.ssrf — superagent.get/post/put/patch/head/del/delete(url)
//   - js.superagent.client.ssrf — superagent(method, url)
//   - js.needle.method.ssrf — needle.get/post/put/patch/delete/head(url)
//   - js.ky.method.ssrf     — ky.get/post/put/patch/delete/head(url)
//   - js.phin.ssrf          — phin(url) / phin({url})
//
// Each entry pins ObjectType to the library's canonical receiver name so an
// unrelated `.get`/`.post`/`.head`/`.stream` method on some other object does
// not false-fire — the negative tests at the bottom verify that scoping.

// --- js.axios.client.ssrf: bare callable form ---

func TestJS_Axios_CallableForm_SSRF(t *testing.T) {
	code := `
function proxy(req, res) {
    const target = req.query.target;
    axios("http://" + target + "/api/v1/data");
}
`
	flows := Analyze(code, "/app/routes/proxy.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.axios.client.ssrf") {
		t.Error("expected js.axios.client.ssrf flow from req.query -> axios(url)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- js.axios.head.ssrf ---

func TestJS_Axios_Head_SSRF(t *testing.T) {
	code := `
function exists(req, res) {
    const url = req.body.url;
    axios.head(url);
}
`
	flows := Analyze(code, "/app/routes/exists.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.axios.head.ssrf") {
		t.Error("expected js.axios.head.ssrf flow from req.body -> axios.head()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- js.https.get.ssrf ---

func TestJS_Https_Get_SSRF(t *testing.T) {
	code := `
function fetchRemote(req, res) {
    const host = req.query.host;
    https.get("https://" + host + "/status", (r) => res);
}
`
	flows := Analyze(code, "/app/routes/remote.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.https.get.ssrf") {
		t.Error("expected js.https.get.ssrf flow from req.query -> https.get()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- js.got.method.ssrf: got.get / got.post ---

func TestJS_Got_Get_SSRF(t *testing.T) {
	code := `
function relay(req, res) {
    const upstream = req.query.upstream;
    got.get("http://" + upstream + "/v1/me");
}
`
	flows := Analyze(code, "/app/routes/relay.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.got.method.ssrf") {
		t.Error("expected js.got.method.ssrf flow from req.query -> got.get()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJS_Got_Post_SSRF(t *testing.T) {
	code := `
function forward(req, res) {
    const dest = req.body.dest;
    got.post("http://" + dest + "/ingest", { json: { ok: true } });
}
`
	flows := Analyze(code, "/app/routes/forward.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.got.method.ssrf") {
		t.Error("expected js.got.method.ssrf flow from req.body -> got.post()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- js.got.stream.ssrf ---

func TestJS_Got_Stream_SSRF(t *testing.T) {
	code := `
function streamProxy(req, res) {
    const url = req.query.url;
    got.stream(url).pipe(res);
}
`
	flows := Analyze(code, "/app/routes/stream.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.got.stream.ssrf") {
		t.Error("expected js.got.stream.ssrf flow from req.query -> got.stream()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- js.got.paginate.ssrf ---

func TestJS_Got_Paginate_SSRF(t *testing.T) {
	code := `
async function collect(req, res) {
    const base = req.query.base;
    for await (const item of got.paginate("http://" + base + "/list")) {
        res.write(item);
    }
}
`
	flows := Analyze(code, "/app/routes/collect.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.got.paginate.ssrf") {
		t.Error("expected js.got.paginate.ssrf flow from req.query -> got.paginate()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- js.superagent.method.ssrf: superagent.get / superagent.post ---

func TestJS_Superagent_Get_SSRF(t *testing.T) {
	code := `
function passthrough(req, res) {
    const target = req.query.target;
    superagent.get("http://" + target + "/data").then((r) => res.send(r.body));
}
`
	flows := Analyze(code, "/app/routes/passthrough.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.superagent.method.ssrf") {
		t.Error("expected js.superagent.method.ssrf flow from req.query -> superagent.get()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJS_Superagent_Post_SSRF(t *testing.T) {
	code := `
function publish(req, res) {
    const hook = req.body.hook;
    superagent.post(hook).send({ event: "ping" });
}
`
	flows := Analyze(code, "/app/routes/publish.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.superagent.method.ssrf") {
		t.Error("expected js.superagent.method.ssrf flow from req.body -> superagent.post()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- js.superagent.client.ssrf: superagent(method, url) callable form ---

func TestJS_Superagent_CallableForm_SSRF(t *testing.T) {
	code := `
function relay(req, res) {
    const target = req.query.target;
    superagent("GET", "http://" + target + "/api");
}
`
	flows := Analyze(code, "/app/routes/relay2.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.superagent.client.ssrf") {
		t.Error("expected js.superagent.client.ssrf flow from req.query -> superagent('GET', url)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- js.needle.method.ssrf: needle.get ---

func TestJS_Needle_Get_SSRF(t *testing.T) {
	code := `
function proxy(req, res) {
    const url = req.query.url;
    needle.get(url, (err, r) => res.send(r.body));
}
`
	flows := Analyze(code, "/app/routes/needle.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.needle.method.ssrf") {
		t.Error("expected js.needle.method.ssrf flow from req.query -> needle.get()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- js.ky.method.ssrf: ky.get ---

func TestJS_Ky_Get_SSRF(t *testing.T) {
	code := `
async function fetchJson(req, res) {
    const target = req.body.target;
    const data = await ky.get("https://" + target + "/v1").json();
    res.json(data);
}
`
	flows := Analyze(code, "/app/routes/ky.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.ky.method.ssrf") {
		t.Error("expected js.ky.method.ssrf flow from req.body -> ky.get()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- js.phin.ssrf: phin(url) ---

func TestJS_Phin_CallableForm_SSRF(t *testing.T) {
	code := `
function probe(req, res) {
    const url = req.query.url;
    phin(url, (err, r) => res.send("done"));
}
`
	flows := Analyze(code, "/app/routes/phin.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.phin.ssrf") {
		t.Error("expected js.phin.ssrf flow from req.query -> phin(url)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJS_Phin_ConfigObjectForm_SSRF(t *testing.T) {
	code := `
function probe(req, res) {
    const target = req.body.target;
    phin({ url: target, method: "GET" });
}
`
	flows := Analyze(code, "/app/routes/phin2.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.phin.ssrf") {
		t.Error("expected js.phin.ssrf flow from req.body -> phin({url})")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Negative: hardcoded literal URL — no SSRF flow expected ---

func TestJS_SSRFClients_LiteralURL_NoFlow(t *testing.T) {
	code := `
function healthcheck(req, res) {
    axios("https://api.internal.svc/health");
    got.get("https://api.internal.svc/ready");
    https.get("https://api.internal.svc/live");
    res.send("ok");
}
`
	flows := Analyze(code, "/app/routes/health.js", rules.LangJavaScript)
	for _, id := range []string{"js.axios.client.ssrf", "js.got.method.ssrf", "js.https.get.ssrf"} {
		if flowMatchesSinkID(flows, id) {
			t.Errorf("expected NO %s flow for hardcoded literal URL", id)
		}
	}
	for _, f := range flows {
		t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
	}
}

// --- Negative: receiver scoping — a `.get()` on an unrelated object (a cache,
// a Map, etc.) must NOT be flagged as got/ky/needle/superagent SSRF. ---

func TestJS_SSRFClients_UnrelatedReceiver_ScopedOut(t *testing.T) {
	code := `
function lookup(req, res) {
    const key = req.query.key;
    const v = cache.get(key);
    res.send(String(v));
}
`
	flows := Analyze(code, "/app/routes/lookup.js", rules.LangJavaScript)
	for _, id := range []string{"js.got.method.ssrf", "js.ky.method.ssrf", "js.needle.method.ssrf", "js.superagent.method.ssrf", "js.https.get.ssrf"} {
		if flowMatchesSinkID(flows, id) {
			t.Errorf("expected NO %s flow for cache.get() — receiver scoping must exclude unrelated objects", id)
			for _, f := range flows {
				t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
			}
		}
	}
}

// --- Negative: http.get must hit the existing js.http.get.ssrf, NOT the new
// https-scoped sink (verifies the two module receivers stay distinct). ---

func TestJS_Http_Get_NotMisattributedToHttps(t *testing.T) {
	code := `
function fetchRemote(req, res) {
    const host = req.query.host;
    http.get("http://" + host + "/status");
}
`
	flows := Analyze(code, "/app/routes/http.js", rules.LangJavaScript)
	if flowMatchesSinkID(flows, "js.https.get.ssrf") {
		t.Error("expected NO js.https.get.ssrf flow for http.get() — must remain js.http.get.ssrf")
	}
	if !flowMatchesSinkID(flows, "js.http.get.ssrf") {
		t.Error("expected js.http.get.ssrf flow from req.query -> http.get() (regression check)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Catalog registration: the new sinks are present for both JS and TS. ---

func TestJS_SSRFClients_CatalogRegistration(t *testing.T) {
	want := []string{
		"js.axios.client.ssrf", "js.axios.head.ssrf", "js.https.get.ssrf",
		"js.got.method.ssrf", "js.got.stream.ssrf", "js.got.paginate.ssrf",
		"js.superagent.method.ssrf", "js.superagent.client.ssrf",
		"js.needle.method.ssrf", "js.ky.method.ssrf", "js.phin.ssrf",
	}
	jsSinks := taint.SinksForLanguage(rules.LangJavaScript)
	for _, id := range want {
		found := false
		for _, s := range jsSinks {
			if s.ID == id {
				found = true
				if s.Category != taint.SnkURLFetch {
					t.Errorf("%s: expected category SnkURLFetch, got %v", id, s.Category)
				}
				if s.CWEID != "CWE-918" {
					t.Errorf("%s: expected CWE-918, got %q", id, s.CWEID)
				}
				break
			}
		}
		if !found {
			t.Errorf("JS sink %q not registered", id)
		}
	}
	tsSinks := taint.SinksForLanguage(rules.LangTypeScript)
	for _, id := range want {
		tsID := "ts." + id[3:]
		found := false
		for _, s := range tsSinks {
			if s.ID == tsID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("TS sink %q not registered", tsID)
		}
	}
}
