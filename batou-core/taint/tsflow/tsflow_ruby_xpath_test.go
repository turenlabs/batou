package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Ruby XPath injection — REXML Element methods + libxml-ruby (CWE-643)
// =========================================================================
//
// These tests exercise the XPath sinks added alongside this file:
//   - ruby.rexml.element.get_elements
//   - ruby.rexml.element.each_element
//   - ruby.rexml.elements.delete_all
//   - ruby.libxml.xpath.expression.new
//   - ruby.libxml.node.find_first

func TestRuby_XPath_REXML_GetElements_Tainted(t *testing.T) {
	code := `
require "rexml/document"

def handler(params)
  xpath = params[:xpath]
  doc = REXML::Document.new(xml_string)
  matches = doc.get_elements(xpath)
  matches.each { |m| puts m }
end
`
	flows := Analyze(code, "/app/controllers/reports_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath flow for params -> REXML Document#get_elements")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_XPath_REXML_EachElement_Tainted(t *testing.T) {
	code := `
require "rexml/document"

def handler(params)
  query = params[:q]
  doc = REXML::Document.new(xml_string)
  doc.each_element(query) do |el|
    puts el.text
  end
end
`
	flows := Analyze(code, "/app/controllers/reports_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath flow for params -> REXML Element#each_element")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_XPath_REXML_ElementsDeleteAll_Tainted(t *testing.T) {
	code := `
require "rexml/document"

def handler(params)
  target = params[:remove]
  doc = REXML::Document.new(xml_string)
  doc.elements.delete_all(target)
end
`
	flows := Analyze(code, "/app/controllers/admin_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath flow for params -> REXML Elements#delete_all")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_XPath_LibXML_ExpressionNew_Tainted(t *testing.T) {
	code := `
require "libxml"

def handler(params)
  expr = params[:xpath]
  compiled = XML::XPath::Expression.new(expr)
  doc.root.find(compiled)
end
`
	flows := Analyze(code, "/app/controllers/search_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath flow for params -> LibXML XML::XPath::Expression.new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_XPath_LibXML_FindFirst_Tainted(t *testing.T) {
	code := `
require "libxml"

def handler(params)
  xpath = params[:xpath]
  doc = XML::Document.file("/var/data/records.xml")
  node = doc.find_first(xpath)
  puts node.content if node
end
`
	flows := Analyze(code, "/app/controllers/records_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath flow for params -> LibXML Node#find_first")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Negative cases ---

// Hardcoded XPath literal — no tainted source reaches the sink.
func TestRuby_XPath_REXML_GetElements_HardcodedSafe(t *testing.T) {
	code := `
require "rexml/document"

def handler(params)
  doc = REXML::Document.new(xml_string)
  matches = doc.get_elements("//user[@id='root']")
end
`
	flows := Analyze(code, "/app/controllers/reports_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("hardcoded XPath literal must not fire REXML get_elements XPath sink")
	}
}

// find_first on a non-libxml receiver must not be confused as an XPath sink
// if the argument is never tainted. This verifies the sink still requires
// tainted data flow rather than matching on the bare method name alone.
func TestRuby_XPath_LibXML_FindFirst_HardcodedSafe(t *testing.T) {
	code := `
require "libxml"

def handler(params)
  doc = XML::Document.file("/var/data/records.xml")
  node = doc.find_first("//record[@id='1']")
end
`
	flows := Analyze(code, "/app/controllers/records_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("hardcoded XPath literal must not fire LibXML find_first XPath sink")
	}
}
