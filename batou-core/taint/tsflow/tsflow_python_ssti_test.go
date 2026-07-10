package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// --- Chameleon SSTI (CWE-1336) ---

func TestPython_SSTI_ChameleonPageTemplate(t *testing.T) {
	code := `
from flask import request
from chameleon import PageTemplate

def handler():
    source = request.args.get("tpl")
    template = PageTemplate(source)
    return template()
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow when user input goes to chameleon.PageTemplate()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_SSTI_ChameleonPageTemplateString(t *testing.T) {
	code := `
from flask import request
from chameleon import PageTemplateString

def handler():
    source = request.args.get("tpl")
    template = PageTemplateString(source)
    return template()
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow when user input goes to chameleon.PageTemplateString()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Cheetah SSTI (CWE-1336) ---

func TestPython_SSTI_CheetahTemplate(t *testing.T) {
	code := `
from flask import request
import Cheetah.Template

def handler():
    source = request.args.get("tpl")
    t = Cheetah.Template.Template(source=source)
    return str(t)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow when user input goes to Cheetah.Template.Template()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Tornado SSTI (CWE-1336) ---

func TestPython_SSTI_TornadoTemplate(t *testing.T) {
	code := `
from flask import request
import tornado.template

def handler():
    source = request.args.get("tpl")
    t = tornado.template.Template(source)
    return t.generate()
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow when user input goes to tornado.template.Template()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Genshi SSTI (CWE-1336) ---

func TestPython_SSTI_GenshiMarkupTemplate(t *testing.T) {
	code := `
from flask import request
from genshi.template import MarkupTemplate

def handler():
    source = request.args.get("tpl")
    tmpl = MarkupTemplate(source)
    return tmpl.generate().render()
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow when user input goes to MarkupTemplate()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_SSTI_GenshiTextTemplate(t *testing.T) {
	code := `
from flask import request
from genshi.template import TextTemplate

def handler():
    source = request.args.get("tpl")
    tmpl = TextTemplate(source)
    return tmpl.generate().render()
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow when user input goes to TextTemplate()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Bottle SimpleTemplate SSTI (CWE-1336) ---

func TestPython_SSTI_BottleSimpleTemplate(t *testing.T) {
	code := `
from flask import request
from bottle import SimpleTemplate

def handler():
    source = request.args.get("tpl")
    tmpl = SimpleTemplate(source)
    return tmpl.render()
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow when user input goes to SimpleTemplate()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Safe: hardcoded template string ---

func TestPython_SSTI_Chameleon_Safe_Hardcoded(t *testing.T) {
	code := `
from chameleon import PageTemplate

def handler():
    tmpl = PageTemplate("<html><body>Hello ${name}</body></html>")
    return tmpl(name="World")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTemplate {
			t.Error("expected NO SSTI flow when template source is hardcoded")
		}
	}
}
