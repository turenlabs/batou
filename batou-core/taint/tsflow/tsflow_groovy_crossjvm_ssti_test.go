package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Groovy cross-JVM SSTI tests (CWE-1336)
//
// Groovy code (Grails, Jenkins pipelines, Gradle scripts) commonly uses
// Java templating libraries via JVM interop. Each compiles or renders a
// template string/name at runtime; tainted input enables RCE:
//   - Apache Velocity (CVE-2020-13936)
//   - FreeMarker
//   - Thymeleaf (CVE-2017-1000480, CVE-2023-38286)
//   - Pebble (CVE-2020-14967, CVE-2021-36380)
//   - Handlebars.java (CVE-2019-10172, CVE-2023-32695)
// =========================================================================

// --- Apache Velocity ---

func TestGroovy_Velocity_Engine_Evaluate_Tainted(t *testing.T) {
	code := `
def handler(userInput) {
    def ve = new VelocityEngine()
    ve.init()
    def writer = new StringWriter()
    ve.evaluate(context, writer, "log-tag", userInput)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow for userInput -> VelocityEngine.evaluate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_Velocity_MergeTemplate_Tainted(t *testing.T) {
	code := `
def handler(userInput) {
    def ve = new VelocityEngine()
    ve.init()
    ve.mergeTemplate(userInput, "UTF-8", context, writer)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow for userInput -> VelocityEngine.mergeTemplate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_Velocity_Template_Merge_Tainted(t *testing.T) {
	code := `
def handler(userInput) {
    def template = ve.getTemplate("greeting.vm")
    def context = new VelocityContext()
    context.put("user", userInput)
    template.merge(context, writer)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow for userInput -> Template.merge (via context)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- FreeMarker ---

func TestGroovy_FreeMarker_Template_Process_Tainted(t *testing.T) {
	code := `
def handler(userInput) {
    def cfg = new Configuration(Configuration.VERSION_2_3_32)
    def template = cfg.getTemplate("greeting.ftl")
    def dataModel = [name: userInput]
    template.process(dataModel, writer)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow for userInput -> FreeMarker Template.process")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_FreeMarker_Configuration_GetTemplate_Tainted(t *testing.T) {
	code := `
def handler(userInput) {
    def configuration = new Configuration(Configuration.VERSION_2_3_32)
    def template = configuration.getTemplate(userInput)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow for userInput -> Configuration.getTemplate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Thymeleaf ---

func TestGroovy_Thymeleaf_TemplateEngine_Process_Tainted(t *testing.T) {
	code := `
def handler(userInput) {
    def templateEngine = new SpringTemplateEngine()
    def ctx = new Context()
    ctx.setVariable("name", "static-value")
    def rendered = templateEngine.process(userInput, ctx)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow for userInput -> TemplateEngine.process")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Pebble ---

func TestGroovy_Pebble_Engine_GetTemplate_Tainted(t *testing.T) {
	code := `
def handler(userInput) {
    def pebbleEngine = new PebbleEngine.Builder().build()
    def template = pebbleEngine.getTemplate(userInput)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow for userInput -> PebbleEngine.getTemplate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_Pebble_Template_Evaluate_Tainted(t *testing.T) {
	code := `
def handler(userInput) {
    def pebbleEngine = new PebbleEngine.Builder().build()
    def pebbleTemplate = pebbleEngine.getTemplate("welcome.peb")
    def context = [name: userInput]
    pebbleTemplate.evaluate(writer, context)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow for userInput -> PebbleTemplate.evaluate (via context)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Handlebars.java ---

func TestGroovy_Handlebars_Compile_Tainted(t *testing.T) {
	code := `
def handler(userInput) {
    def handlebars = new Handlebars()
    def template = handlebars.compile(userInput)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow for userInput -> Handlebars.compile")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_Handlebars_CompileInline_Tainted(t *testing.T) {
	code := `
def handler(userInput) {
    def handlebars = new Handlebars()
    def template = handlebars.compileInline(userInput)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow for userInput -> Handlebars.compileInline")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Safe fixtures ---

// Safe: template name is a string literal and template.process is called with
// a static data model that does not include userInput.
func TestGroovy_FreeMarker_StaticTemplate_Safe(t *testing.T) {
	code := `
def handler(userInput) {
    def cfg = new Configuration(Configuration.VERSION_2_3_32)
    def template = cfg.getTemplate("greeting.ftl")
    def dataModel = [greeting: "hello"]
    template.process(dataModel, writer)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTemplate {
			t.Errorf("unexpected SSTI flow when template name is literal and model is static: %s -> %s",
				f.Source.Category, f.Sink.Category)
		}
	}
}

// Safe: Velocity.evaluate receives a static template literal; context values
// live in the writer/context, not the template source arg (arg 3).
func TestGroovy_Velocity_StaticTemplate_Safe(t *testing.T) {
	code := `
def handler(userInput) {
    def ve = new VelocityEngine()
    ve.init()
    ve.evaluate(context, writer, "log-tag", "Hello, \$name!")
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTemplate {
			t.Errorf("unexpected SSTI flow when Velocity.evaluate template arg is a literal: %s -> %s",
				f.Source.Category, f.Sink.Category)
		}
	}
}
