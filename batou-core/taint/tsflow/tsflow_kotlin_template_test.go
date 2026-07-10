package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Kotlin template injection sinks — Apache Velocity, Pebble, Handlebars.java,
// Mustache.java, JTE (CWE-1336)
// =========================================================================

// --- Apache Velocity ---

func TestKotlin_Velocity_MergeTemplate_Vulnerable(t *testing.T) {
	code := `
fun handler() {
    val tmplName = readLine()
    val velocityEngine = VelocityEngine()
    val ctx = VelocityContext()
    velocityEngine.mergeTemplate(tmplName, "UTF-8", ctx, writer)
}
`
	flows := Analyze(code, "/app/Service.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow for readLine -> velocityEngine.mergeTemplate()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_Velocity_Evaluate_Vulnerable(t *testing.T) {
	code := `
fun handler() {
    val tmpl = readLine()
    val ctx = VelocityContext()
    Velocity.evaluate(ctx, writer, "logTag", tmpl)
}
`
	flows := Analyze(code, "/app/Service.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow for readLine -> Velocity.evaluate()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Pebble ---

func TestKotlin_Pebble_GetTemplate_Vulnerable(t *testing.T) {
	code := `
fun handler() {
    val tmplName = readLine()
    val pebbleEngine = PebbleEngine.Builder().build()
    val template = pebbleEngine.getTemplate(tmplName)
    template.evaluate(writer, mapOf("user" to "bob"))
}
`
	flows := Analyze(code, "/app/Service.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow for readLine -> pebbleEngine.getTemplate()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Handlebars.java ---

func TestKotlin_Handlebars_Compile_Vulnerable(t *testing.T) {
	code := `
fun handler() {
    val userTemplate = readLine()
    val handlebars = Handlebars()
    val template = handlebars.compileInline(userTemplate)
    template.apply(mapOf("user" to "bob"))
}
`
	flows := Analyze(code, "/app/Service.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow for readLine -> handlebars.compileInline()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Mustache.java ---

func TestKotlin_Mustache_Compile_Vulnerable(t *testing.T) {
	code := `
fun handler() {
    val tmplName = readLine()
    val mustacheFactory = DefaultMustacheFactory()
    val mustache = mustacheFactory.compile(tmplName)
    mustache.execute(writer, mapOf("name" to "bob"))
}
`
	flows := Analyze(code, "/app/Service.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow for readLine -> mustacheFactory.compile()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- JTE ---

func TestKotlin_JTE_Render_Vulnerable(t *testing.T) {
	code := `
fun handler() {
    val page = readLine()
    val templateEngine = TemplateEngine.create(resolver, ContentType.Html)
    templateEngine.render(page, mapOf("user" to "bob"), output)
}
`
	flows := Analyze(code, "/app/Service.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow for readLine -> templateEngine.render()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Safe: hardcoded template name (not tainted) ---

func TestKotlin_Velocity_MergeTemplate_Safe(t *testing.T) {
	code := `
fun handler() {
    val velocityEngine = VelocityEngine()
    val ctx = VelocityContext()
    velocityEngine.mergeTemplate("welcome.vm", "UTF-8", ctx, writer)
}
`
	flows := Analyze(code, "/app/Service.kt", rules.LangKotlin)
	if hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected no SSTI flow for hardcoded template name")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_Handlebars_Compile_Safe(t *testing.T) {
	code := `
fun handler() {
    val handlebars = Handlebars()
    val template = handlebars.compileInline("Hello {{name}}")
    template.apply(mapOf("name" to "world"))
}
`
	flows := Analyze(code, "/app/Service.kt", rules.LangKotlin)
	if hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected no SSTI flow for hardcoded template source")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
