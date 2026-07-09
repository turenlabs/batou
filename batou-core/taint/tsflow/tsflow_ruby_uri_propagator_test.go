package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// TestRuby_SSRF_NetHTTP_URI_Wrap_SinatraBlock pins the canonical CWE-918
// shape from the rubycve-bench classic-ruby-ssrf fixture: a Sinatra
// route reads params[:url] and fetches it with Net::HTTP.get(URI(...)).
// The Kernel#URI() wrap must not strip the taint, and the Sinatra
// `get ... do ... end` route block must be analysed as its own scope by
// the tsflow walker (handled via langconfig.findExtraScopes for Ruby).
func TestRuby_SSRF_NetHTTP_URI_Wrap_SinatraBlock(t *testing.T) {
	code := `
require "sinatra/base"
require "net/http"
require "uri"

class FetchApp < Sinatra::Base
  get "/fetch" do
    target = params[:url]
    body = Net::HTTP.get(URI(target))
    content_type :text
    body
  end
end
`
	flows := Analyze(code, "/app/fetch_app.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Errorf("expected SSRF flow for params[:url] -> Net::HTTP.get(URI(target)) inside Sinatra get block; got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// TestRuby_DESER_Psych_UnsafeLoad_SinatraBlock pins CVE-2022-32224 in
// its Sinatra-route form: an HTTP-supplied blob fed to Psych.unsafe_load
// inside a `post "/x" do ... end` block. Same DSL-scope path as the SSRF
// case above.
func TestRuby_DESER_Psych_UnsafeLoad_SinatraBlock(t *testing.T) {
	code := `
require "sinatra/base"
require "psych"

class SettingsStore < Sinatra::Base
  post "/settings" do
    blob = params[:settings]
    parsed = Psych.unsafe_load(blob)
    content_type :json
    parsed.to_json
  end
end
`
	flows := Analyze(code, "/app/settings_store.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Errorf("expected deser flow for params[:settings] -> Psych.unsafe_load(blob) inside Sinatra post block; got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// TestRuby_ERB_Injection_SinatraBlock pins CVE-2020-8163: tainted name
// interpolated into ERB.new() inside a Sinatra route. ERB.new is
// registered as SnkTemplate (CWE-1336); the per-language class-aware
// CWE table maps 1336 → 94 so the rubycve bench accepts either.
func TestRuby_ERB_Injection_SinatraBlock(t *testing.T) {
	code := `
require "sinatra/base"
require "erb"

class RenderController < Sinatra::Base
  get "/render" do
    name = params[:name]
    template = "Hello, <%= #{name} %>"
    ERB.new(template).result(binding)
  end
end
`
	flows := Analyze(code, "/app/render_controller.rb", rules.LangRuby)
	if len(flows) == 0 {
		t.Errorf("expected ERB injection flow for params[:name] -> ERB.new(template); got %d flows", len(flows))
	}
}
