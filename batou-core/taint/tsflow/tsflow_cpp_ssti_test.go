package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// C++ SSTI / template injection tests (CWE-1336)
//
// These tests cover popular C++ template engines where user-controlled input
// reaches the template-source argument, enabling server-side template
// injection. Rendering arguments (data context) are a separate flow and are
// not covered here — only the template-source argument is dangerous for SSTI.
//
// Engines covered:
//   - mstch (header-only Mustache, "mstch::render(tpl, ctx)")
//   - Crow framework Mustache ("crow::mustache::compile(tpl)")
//   - kainjow::mustache constructor
//   - Google ctemplate (StringToTemplateCache / ExpandTemplate)
// =========================================================================

func TestCPP_Mstch_Render_Tainted(t *testing.T) {
	code := `
#include <mstch/mstch.hpp>
#include <cstdlib>
#include <string>

std::string render_page() {
    const char *raw = std::getenv("TEMPLATE_SRC");
    std::string tpl = raw;
    mstch::map ctx{{"name", std::string("world")}};
    return mstch::render(tpl, ctx);
}
`
	flows := Analyze(code, "/app/mstch_handler.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow for getenv -> mstch::render")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Mstch_Render_Safe(t *testing.T) {
	code := `
#include <mstch/mstch.hpp>
#include <string>

std::string render_page() {
    std::string tpl = "Hello {{name}}";
    mstch::map ctx{{"name", std::string("world")}};
    return mstch::render(tpl, ctx);
}
`
	flows := Analyze(code, "/app/mstch_safe.cpp", rules.LangCPP)
	if hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected NO SSTI flow when template is a literal")
	}
}

func TestCPP_Crow_Mustache_Compile_Tainted(t *testing.T) {
	code := `
#include <crow/mustache.h>
#include <cstdlib>
#include <string>

std::string render_page() {
    const char *raw = std::getenv("CROW_TEMPLATE");
    std::string tpl_source = raw;
    auto page = crow::mustache::compile(tpl_source);
    return page.render_string();
}
`
	flows := Analyze(code, "/app/crow_handler.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow for getenv -> crow::mustache::compile")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_CTemplate_StringCache_Tainted(t *testing.T) {
	code := `
#include <ctemplate/template.h>
#include <cstdlib>
#include <string>

void register_template() {
    const char *raw = std::getenv("TPL_BODY");
    std::string body = raw;
    ctemplate::StringToTemplateCache("user_tpl", body, ctemplate::STRIP_WHITESPACE);
}
`
	flows := Analyze(code, "/app/ctemplate_handler.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow for getenv -> ctemplate::StringToTemplateCache")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_CTemplate_Expand_Tainted(t *testing.T) {
	code := `
#include <ctemplate/template.h>
#include <cstdlib>
#include <string>

void render_to(std::string *output) {
    const char *raw = std::getenv("TPL_FILE");
    std::string tpl_name = raw;
    ctemplate::TemplateDictionary dict("dict");
    ctemplate::ExpandTemplate(tpl_name, ctemplate::STRIP_WHITESPACE, &dict, output);
}
`
	flows := Analyze(code, "/app/ctemplate_expand.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected template-path flow for getenv -> ctemplate::ExpandTemplate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
