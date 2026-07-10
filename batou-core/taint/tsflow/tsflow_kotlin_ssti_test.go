package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// ---------- Apache Velocity (CWE-1336) ----------

func TestKotlin_VelocityEvaluate(t *testing.T) {
	code := `
import org.apache.velocity.app.VelocityEngine
import org.apache.velocity.VelocityContext
import java.io.StringWriter

fun render(request: HttpServletRequest) {
    val tmpl = request.getParameter("tmpl")
    val velocity = VelocityEngine()
    val writer = StringWriter()
    val ctx = VelocityContext()
    velocity.evaluate(ctx, writer, "tag", tmpl)
}
`
	flows := Analyze(code, "/app/VelocityController.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTemplate && f.Sink.ID == "kotlin.velocity.evaluate" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected template injection flow for Velocity.evaluate, got: %+v", flows)
	}
}

func TestKotlin_VelocityMergeTemplate(t *testing.T) {
	code := `
import org.apache.velocity.app.VelocityEngine
import org.apache.velocity.VelocityContext
import java.io.StringWriter

fun renderByName(request: HttpServletRequest) {
    val name = request.getParameter("t")
    val velocity = VelocityEngine()
    val writer = StringWriter()
    val ctx = VelocityContext()
    velocity.mergeTemplate(name, "UTF-8", ctx, writer)
}
`
	flows := Analyze(code, "/app/VelocityController.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTemplate && f.Sink.ID == "kotlin.velocity.mergetemplate" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected template injection flow for Velocity.mergeTemplate, got: %+v", flows)
	}
}

func TestKotlin_VelocityTemplateMerge(t *testing.T) {
	code := `
import org.apache.velocity.Template
import org.apache.velocity.VelocityContext
import java.io.StringWriter

fun render(request: HttpServletRequest, template: Template) {
    val userData = request.getParameter("data")
    val ctx = VelocityContext()
    ctx.put("data", userData)
    val writer = StringWriter()
    template.merge(ctx, writer)
}
`
	flows := Analyze(code, "/app/VelocityController.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTemplate && f.Sink.ID == "kotlin.velocity.template.merge" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected template injection flow for Template.merge, got: %+v", flows)
	}
}

// ---------- Pebble (CWE-1336) ----------

func TestKotlin_PebbleGetTemplate(t *testing.T) {
	code := `
import com.mitchellbosecke.pebble.PebbleEngine
import java.io.StringWriter

fun render(request: HttpServletRequest) {
    val name = request.getParameter("tmpl")
    val engine = PebbleEngine.Builder().build()
    val pebbleEngine = engine
    val t = pebbleEngine.getTemplate(name)
    val writer = StringWriter()
    t.evaluate(writer, mapOf<String, Any>())
}
`
	flows := Analyze(code, "/app/PebbleController.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTemplate && f.Sink.ID == "kotlin.pebble.gettemplate" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected template injection flow for PebbleEngine.getTemplate, got: %+v", flows)
	}
}

func TestKotlin_PebbleTemplateEvaluate(t *testing.T) {
	code := `
import com.mitchellbosecke.pebble.PebbleEngine
import com.mitchellbosecke.pebble.template.PebbleTemplate
import java.io.StringWriter

fun render(request: HttpServletRequest, template: PebbleTemplate) {
    val data = request.getParameter("ctx")
    val writer = StringWriter()
    template.evaluate(writer, data)
}
`
	flows := Analyze(code, "/app/PebbleController.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTemplate && f.Sink.ID == "kotlin.pebble.template.evaluate" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected template injection flow for PebbleTemplate.evaluate, got: %+v", flows)
	}
}

// ---------- Handlebars.java (CWE-1336) ----------

func TestKotlin_HandlebarsCompile(t *testing.T) {
	code := `
import com.github.jknack.handlebars.Handlebars

fun load(request: HttpServletRequest) {
    val name = request.getParameter("tmpl")
    val handlebars = Handlebars()
    val t = handlebars.compile(name)
    println(t)
}
`
	flows := Analyze(code, "/app/HandlebarsController.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTemplate && f.Sink.ID == "kotlin.handlebars.compile" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected template injection flow for Handlebars.compile, got: %+v", flows)
	}
}

func TestKotlin_HandlebarsCompileInline(t *testing.T) {
	code := `
import com.github.jknack.handlebars.Handlebars

fun render(request: HttpServletRequest) {
    val tmpl = request.getParameter("tmpl")
    val handlebars = Handlebars()
    val t = handlebars.compileInline(tmpl)
    println(t)
}
`
	flows := Analyze(code, "/app/HandlebarsController.kt", rules.LangKotlin)
	// The unified `kotlin.handlebars.compile` entry uses a regex that already
	// matches both compile and compileInline, so the matcher returns that ID
	// rather than the more specific `kotlin.handlebars.compileinline`. Either
	// ID counts as a valid Handlebars SSTI flow.
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTemplate &&
			(f.Sink.ID == "kotlin.handlebars.compileinline" || f.Sink.ID == "kotlin.handlebars.compile") {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected template injection flow for Handlebars.compileInline, got: %+v", flows)
	}
}

// ---------- Jinjava (CWE-1336) ----------

func TestKotlin_JinjavaRender(t *testing.T) {
	code := `
import com.hubspot.jinjava.Jinjava

fun render(request: HttpServletRequest) {
    val tmpl = request.getParameter("tmpl")
    val jinjava = Jinjava()
    val result = jinjava.render(tmpl, mapOf<String, Any>("user" to "bob"))
    println(result)
}
`
	flows := Analyze(code, "/app/JinjavaController.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTemplate && f.Sink.ID == "kotlin.jinjava.render" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected template injection flow for Jinjava.render, got: %+v", flows)
	}
}

// ---------- Safe case: constant template name ----------

func TestKotlin_VelocityMergeTemplate_Safe(t *testing.T) {
	code := `
import org.apache.velocity.app.VelocityEngine
import org.apache.velocity.VelocityContext
import java.io.StringWriter

fun renderStatic() {
    val velocity = VelocityEngine()
    val writer = StringWriter()
    val ctx = VelocityContext()
    velocity.mergeTemplate("welcome.vm", "UTF-8", ctx, writer)
}
`
	flows := Analyze(code, "/app/VelocityController.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.ID == "kotlin.velocity.mergetemplate" {
			t.Errorf("Did not expect template injection finding for hardcoded template name, got: %+v", f)
		}
	}
}
