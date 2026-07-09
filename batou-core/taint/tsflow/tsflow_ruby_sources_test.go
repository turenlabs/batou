package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Ruby — Sequel ORM database result sources (second-order injection)
// =========================================================================

func TestRuby_Source_SequelFirst_CommandInjection(t *testing.T) {
	code := `
def process
  row = DB[:commands].first
  system(row[:cmd])
end
`
	flows := Analyze(code, "/app/worker.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from Sequel DB[:table].first")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRuby_Source_SequelAll_SQLInjection(t *testing.T) {
	code := `
require "sequel"

def export
  rows = DB[:user_queries].all
  query = rows.first[:sql]
  DB.run(query)
end
`
	flows := Analyze(code, "/app/export.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from Sequel DB[:table].all")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRuby_Source_SequelGet_SQLInjection(t *testing.T) {
	code := `
def show
  bio = DB[:profiles].get(:bio)
  DB.run(bio)
end
`
	flows := Analyze(code, "/app/profile.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from Sequel DB[:table].get -> DB.run")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRuby_Source_SequelSelectMap_Command(t *testing.T) {
	code := `
def run_scripts
  scripts = DB[:jobs].select_map(:script)
  system(scripts[0])
end
`
	flows := Analyze(code, "/app/scheduler.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from Sequel select_map")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Ruby — Deserialization result sources
// =========================================================================

func TestRuby_Source_YAMLSafeLoad_Command(t *testing.T) {
	code := `
require "yaml"

def process_config(file_data)
  config = YAML.safe_load(file_data)
  system(config["command"])
end
`
	flows := Analyze(code, "/app/config_loader.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from YAML.safe_load result")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRuby_Source_MessagePackUnpack_SQL(t *testing.T) {
	code := `
require "msgpack"

def handle_message(raw_data)
  msg = MessagePack.unpack(raw_data)
  DB.run(msg["query"])
end
`
	flows := Analyze(code, "/app/consumer.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from MessagePack.unpack result")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Ruby — HTTP client response sources (SSRF chain)
// =========================================================================

func TestRuby_Source_HTTPartyParsedResponse_Command(t *testing.T) {
	code := `
require "httparty"

def fetch_and_run(api_url)
  response = HTTParty.get(api_url)
  data = response.parsed_response
  system(data["command"])
end
`
	flows := Analyze(code, "/app/fetcher.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from HTTParty parsed_response")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRuby_Source_URIOpen_Eval(t *testing.T) {
	code := `
require "open-uri"

def load_remote_script(url)
  content = URI.open(url)
  script = content.read
  eval(script)
end
`
	flows := Analyze(code, "/app/loader.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow from URI.open response")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Ruby — Safe fixture (sanitized Sequel data should not flag)
// =========================================================================

func TestRuby_Source_SequelFirst_Sanitized(t *testing.T) {
	code := `
def show
  row = DB[:users].first
  name = CGI.escapeHTML(row[:name])
  response.write(name)
end
`
	flows := Analyze(code, "/app/safe_profile.rb", rules.LangRuby)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Confidence > 0.5 {
			t.Error("should not detect high-confidence XSS when CGI.escapeHTML sanitizes Sequel data")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
