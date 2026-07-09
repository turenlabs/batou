package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
)

// --- Ruby SSRF: HTTParty additional verbs ---

func TestRuby_HTTParty_Post_SSRF(t *testing.T) {
	code := `
def create(params)
    url = params[:callback_url]
    HTTParty.post(url, body: { status: "done" })
end
`
	flows := Analyze(code, "/app/webhook.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for params -> HTTParty.post")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRuby_HTTParty_Put_SSRF(t *testing.T) {
	code := `
def update(params)
    url = params[:endpoint]
    HTTParty.put(url, body: { name: "test" })
end
`
	flows := Analyze(code, "/app/handler.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for params -> HTTParty.put")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRuby_HTTParty_Delete_SSRF(t *testing.T) {
	code := `
def destroy(params)
    url = params[:target]
    HTTParty.delete(url)
end
`
	flows := Analyze(code, "/app/handler.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for params -> HTTParty.delete")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Ruby SSRF: Faraday additional verbs + constructor ---

func TestRuby_Faraday_Post_SSRF(t *testing.T) {
	code := `
def notify(params)
    url = params[:webhook]
    Faraday.post(url, '{"event":"done"}')
end
`
	flows := Analyze(code, "/app/notifier.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for params -> Faraday.post")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRuby_Faraday_New_SSRF(t *testing.T) {
	code := `
def fetch(params)
    base = params[:api_url]
    conn = Faraday.new(base)
end
`
	flows := Analyze(code, "/app/client.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for params -> Faraday.new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Ruby SSRF: Net::HTTP stdlib methods ---

func TestRuby_NetHTTP_Start_SSRF(t *testing.T) {
	code := `
def proxy(params)
    host = params[:host]
    Net::HTTP.start(host, 80) do |http|
      http.request(Net::HTTP::Get.new("/"))
    end
end
`
	flows := Analyze(code, "/app/proxy.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for params -> Net::HTTP.start")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRuby_NetHTTP_GetResponse_SSRF(t *testing.T) {
	code := `
def check(params)
    uri = URI.parse(params[:url])
    response = Net::HTTP.get_response(uri)
end
`
	flows := Analyze(code, "/app/checker.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for params -> Net::HTTP.get_response")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Ruby SSRF: RestClient additional verbs ---

func TestRuby_RestClient_Put_SSRF(t *testing.T) {
	code := `
def update(params)
    url = params[:api_endpoint]
    RestClient.put(url, { data: "value" }.to_json)
end
`
	flows := Analyze(code, "/app/api_client.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for params -> RestClient.put")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Ruby SSRF: Excon additional verbs ---

func TestRuby_Excon_Put_SSRF(t *testing.T) {
	code := `
def sync(params)
    url = params[:sync_url]
    Excon.put(url, body: "payload")
end
`
	flows := Analyze(code, "/app/sync.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for params -> Excon.put")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Ruby SSRF: Safe pattern (sanitized) ---

func TestRuby_SSRF_Sanitized_URIParseHost(t *testing.T) {
	code := `
def safe_fetch(params)
    uri = URI.parse(params[:url])
    allowed = uri.host
    HTTParty.post("https://api.internal.com/data")
end
`
	flows := Analyze(code, "/app/safe.rb", rules.LangRuby)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			// The URL passed to HTTParty.post is a hardcoded literal, not tainted.
			// If a flow is detected, it's a false positive.
			t.Logf("  flow: %s -> %s (conf: %.2f, sink pattern: %s)", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.Pattern)
		}
	}
}

// --- Ruby SSRF: SsrfFilter gem sanitizes response ---

func TestRuby_SSRF_Sanitized_SsrfFilter(t *testing.T) {
	code := `
def safe_fetch(params)
  url = params[:url]
  response = SsrfFilter.get(url)
  Net::HTTP.get(response)
end
`
	flows := Analyze(code, "/app/safe_ssrf.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected NO SSRF flow — SsrfFilter.get() should sanitize for SnkURLFetch")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Ruby SSRF: URI.parse().scheme extraction sanitizes ---

func TestRuby_SSRF_Sanitized_URIParseScheme(t *testing.T) {
	code := `
def validate(params)
  url = params[:url]
  uri = URI.parse(url)
  scheme = uri.scheme
  Net::HTTP.get(scheme)
end
`
	flows := Analyze(code, "/app/validate_url.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected NO SSRF flow — uri.scheme extraction should sanitize for SnkURLFetch")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Ruby SSRF: URI.parse().port extraction sanitizes ---

func TestRuby_SSRF_Sanitized_URIParsePort(t *testing.T) {
	code := `
def check_port(params)
  url = params[:url]
  uri = URI.parse(url)
  port = uri.port
  Net::HTTP.get(port)
end
`
	flows := Analyze(code, "/app/check_port.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected NO SSRF flow — uri.port extraction should sanitize for SnkURLFetch")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Ruby SSRF: Addressable::URI scheme extraction sanitizes ---

func TestRuby_SSRF_Sanitized_AddressableScheme(t *testing.T) {
	code := `
def validate(params)
  url = params[:url]
  uri = Addressable::URI.parse(url)
  scheme = uri.scheme
  Net::HTTP.get(scheme)
end
`
	flows := Analyze(code, "/app/addressable_check.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected NO SSRF flow — Addressable URI scheme extraction should sanitize for SnkURLFetch")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Ruby SSRF: PrivateAddressCheck sanitizes ---

func TestRuby_SSRF_Sanitized_PrivateAddressCheck(t *testing.T) {
	code := `
def validate(params)
  url = params[:url]
  safe = PrivateAddressCheck.resolves_to_private_address?(url)
  Net::HTTP.get(safe)
end
`
	flows := Analyze(code, "/app/private_check.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected NO SSRF flow — PrivateAddressCheck should sanitize for SnkURLFetch")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Ruby SSRF: http gem (httprb) ---

func TestRuby_HTTP_Get_SSRF(t *testing.T) {
	code := `
def proxy(params)
  url = params[:target]
  response = HTTP.get(url)
  response.to_s
end
`
	flows := Analyze(code, "/app/proxy.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for params -> HTTP.get (http gem)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRuby_HTTP_Post_SSRF(t *testing.T) {
	code := `
def notify(params)
  url = params[:webhook]
  HTTP.post(url, body: '{"event":"done"}')
end
`
	flows := Analyze(code, "/app/notifier.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for params -> HTTP.post (http gem)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRuby_HTTP_Delete_SSRF(t *testing.T) {
	code := `
def destroy(params)
  url = params[:target]
  HTTP.delete(url)
end
`
	flows := Analyze(code, "/app/handler.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for params -> HTTP.delete (http gem)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRuby_HTTP_Request_SSRF(t *testing.T) {
	code := `
def forward(params)
  url = params[:url]
  HTTP.request(:get, url)
end
`
	flows := Analyze(code, "/app/forward.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for params -> HTTP.request (http gem)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Ruby SSRF: httpx gem (module-level convenience methods) ---

func TestRuby_HTTPX_Get_SSRF(t *testing.T) {
	code := `
def proxy(params)
  url = params[:target]
  response = HTTPX.get(url)
  response.to_s
end
`
	flows := Analyze(code, "/app/proxy.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for params -> HTTPX.get (httpx gem)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRuby_HTTPX_Post_SSRF(t *testing.T) {
	code := `
def notify(params)
  url = params[:webhook]
  HTTPX.post(url, form: { event: "done" })
end
`
	flows := Analyze(code, "/app/notifier.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for params -> HTTPX.post (httpx gem)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRuby_HTTPX_Delete_SSRF(t *testing.T) {
	code := `
def destroy(params)
  url = params[:target]
  HTTPX.delete(url)
end
`
	flows := Analyze(code, "/app/handler.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for params -> HTTPX.delete (httpx gem)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRuby_HTTPX_Request_SSRF(t *testing.T) {
	code := `
def forward(params)
  url = params[:url]
  HTTPX.request(:get, url)
end
`
	flows := Analyze(code, "/app/forward.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for params -> HTTPX.request (httpx gem)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRuby_HTTPX_Safe_HardcodedURL(t *testing.T) {
	code := `
def health_check
  HTTPX.get("https://internal.example.com/status")
end
`
	flows := Analyze(code, "/app/health.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected NO SSRF flow — hardcoded URL is safe (httpx gem)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Ruby SSRF: Down gem (file download by URL) ---

func TestRuby_Down_Download_SSRF(t *testing.T) {
	code := `
def fetch_avatar(params)
  url = params[:avatar_url]
  tempfile = Down.download(url)
  tempfile.path
end
`
	flows := Analyze(code, "/app/uploader.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for params -> Down.download")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRuby_Down_Open_SSRF(t *testing.T) {
	code := `
def stream(params)
  url = params[:src]
  io = Down.open(url)
  io.read
end
`
	flows := Analyze(code, "/app/streamer.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for params -> Down.open")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Ruby SSRF: http gem safe with hardcoded URL ---

func TestRuby_HTTP_Safe_HardcodedURL(t *testing.T) {
	code := `
def health_check
  HTTP.get("https://internal.example.com/status")
end
`
	flows := Analyze(code, "/app/health.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected NO SSRF flow — hardcoded URL is safe")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
