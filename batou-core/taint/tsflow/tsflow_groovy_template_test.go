package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Groovy template injection tests (CWE-1336, SSTI)
//
// These tests cover Groovy's built-in *TemplateEngine.createTemplate() methods
// which compile the provided source string as Groovy code. If user input
// reaches the source argument, SSTI leads to RCE via arbitrary code
// evaluation.
// =========================================================================

func TestGroovy_MarkupTemplateEngine_CreateTemplate_Tainted(t *testing.T) {
	code := `
def handler(userInput) {
    def markupTemplateEngine = new MarkupTemplateEngine(config)
    def template = markupTemplateEngine.createTemplate(userInput)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected template-injection flow for userInput -> markupTemplateEngine.createTemplate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_StreamingTemplateEngine_CreateTemplate_Tainted(t *testing.T) {
	code := `
def handler(userInput) {
    def streamingTemplateEngine = new StreamingTemplateEngine()
    def template = streamingTemplateEngine.createTemplate(userInput)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected template-injection flow for userInput -> streamingTemplateEngine.createTemplate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_XmlTemplateEngine_CreateTemplate_Tainted(t *testing.T) {
	code := `
def handler(userInput) {
    def xmlTemplateEngine = new XmlTemplateEngine()
    def template = xmlTemplateEngine.createTemplate(userInput)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected template-injection flow for userInput -> xmlTemplateEngine.createTemplate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_GroovyPagesTemplateEngine_CreateTemplate_Tainted(t *testing.T) {
	code := `
def handler(userInput) {
    def groovyPagesTemplateEngine = new GroovyPagesTemplateEngine()
    def template = groovyPagesTemplateEngine.createTemplate(userInput, "page.gsp")
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected template-injection flow for userInput -> groovyPagesTemplateEngine.createTemplate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Safe: a static template literal should not produce a template-injection flow
// even when userInput exists elsewhere (and is only passed to .make() bindings,
// which are evaluated as values — not as template source).
func TestGroovy_MarkupTemplateEngine_StaticTemplate_Safe(t *testing.T) {
	code := `
def handler(userInput) {
    def markupTemplateEngine = new MarkupTemplateEngine(config)
    def template = markupTemplateEngine.createTemplate("p('hello')")
    def result = template.make([name: userInput])
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTemplate {
			t.Errorf("unexpected template-injection flow when createTemplate receives a string literal: %s -> %s",
				f.Source.Category, f.Sink.Category)
		}
	}
}
