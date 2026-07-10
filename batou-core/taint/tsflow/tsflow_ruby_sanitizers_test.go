package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Ruby — Command injection sanitized by String#shellescape (CWE-78)
// =========================================================================

func TestRuby_CommandInjection_Sanitized_StringShellescape(t *testing.T) {
	code := `
require 'shellwords'
def handler(params)
    filename = params[:filename]
    safe = filename.shellescape
    system("ls #{safe}")
end
`
	flows := Analyze(code, "/app/handler.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("String#shellescape should neutralize command injection taint flow")
	}
}

func TestRuby_CommandInjection_Unsanitized_NoShellescape(t *testing.T) {
	code := `
def handler(params)
    filename = params[:filename]
    system("ls #{filename}")
end
`
	flows := Analyze(code, "/app/handler.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow without shellescape")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// =========================================================================
// Ruby — Template injection sanitized by Haml auto-escape (CWE-1336)
// =========================================================================

func TestRuby_Template_Sanitized_HamlEngineRender(t *testing.T) {
	code := `
def handler(params)
    name = params[:name]
    output = Haml::Engine.new("%p= name").render(Object.new, name: name)
    render html: output
end
`
	flows := Analyze(code, "/app/handler.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("Haml::Engine.new().render() should neutralize template injection taint flow")
	}
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("Haml::Engine.new().render() should neutralize HTML output taint flow")
	}
}

// =========================================================================
// Ruby — Template injection sanitized by Mustache.render (CWE-1336)
// =========================================================================

func TestRuby_Template_Sanitized_MustacheRender(t *testing.T) {
	code := `
def handler(params)
    name = params[:name]
    output = Mustache.render("Hello {{name}}", name: name)
    render html: output
end
`
	flows := Analyze(code, "/app/handler.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("Mustache.render() should neutralize template injection taint flow")
	}
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("Mustache.render() should neutralize HTML output taint flow")
	}
}

// =========================================================================
// Ruby — Template injection sanitized by Slim auto-escape (CWE-1336)
// =========================================================================

func TestRuby_Template_Sanitized_SlimTemplateRender(t *testing.T) {
	code := `
def handler(params)
    name = params[:name]
    output = Slim::Template.new("= name").render(Object.new, name: name)
    render html: output
end
`
	flows := Analyze(code, "/app/handler.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("Slim::Template.new().render() should neutralize template injection taint flow")
	}
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("Slim::Template.new().render() should neutralize HTML output taint flow")
	}
}

// =========================================================================
// Ruby — Log injection sanitized by Oj.dump (CWE-117)
// =========================================================================

func TestRuby_Log_Sanitized_OjDump(t *testing.T) {
	code := `
def create(params)
    username = params[:username]
    safe = Oj.dump(username)
    logger.info("Login: " + safe)
end
`
	flows := Analyze(code, "/app/controllers/auth_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkLog) {
		t.Error("Oj.dump should neutralize log injection taint flow")
	}
}

// =========================================================================
// Ruby — Log injection sanitized by MultiJson.dump (CWE-117)
// =========================================================================

func TestRuby_Log_Sanitized_MultiJsonDump(t *testing.T) {
	code := `
def create(params)
    username = params[:username]
    safe = MultiJson.dump(username)
    logger.info("Login: " + safe)
end
`
	flows := Analyze(code, "/app/controllers/auth_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkLog) {
		t.Error("MultiJson.dump should neutralize log injection taint flow")
	}
}

func TestRuby_Log_Sanitized_MultiJsonEncode(t *testing.T) {
	code := `
def create(params)
    data = params[:data]
    safe = MultiJson.encode(data)
    logger.warn("Data: " + safe)
end
`
	flows := Analyze(code, "/app/controllers/api_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkLog) {
		t.Error("MultiJson.encode should neutralize log injection taint flow")
	}
}
