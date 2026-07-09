package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// --- libxml: Context::findnodes (CWE-643) ---

func TestRust_Libxml_Findnodes(t *testing.T) {
	code := `
use std::env;
use libxml::parser::Parser;
use libxml::xpath::Context;

fn handle() {
    let expr = env::var("XPATH").unwrap();
    let parser = Parser::default();
    let doc = parser.parse_string("<a/>").unwrap();
    let ctx = Context::new(&doc).unwrap();
    let nodes = ctx.findnodes(&expr, None);
}
`
	flows := Analyze(code, "/app/xml.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath flow for env::var -> libxml Context::findnodes")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- libxml: Context::findvalue (CWE-643) ---

func TestRust_Libxml_Findvalue(t *testing.T) {
	code := `
use std::env;
use libxml::parser::Parser;
use libxml::xpath::Context;

fn handle() {
    let expr = env::var("XPATH").unwrap();
    let parser = Parser::default();
    let doc = parser.parse_string("<a/>").unwrap();
    let ctx = Context::new(&doc).unwrap();
    let v = ctx.findvalue(&expr, None);
}
`
	flows := Analyze(code, "/app/xml.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath flow for env::var -> libxml Context::findvalue")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- libxml: Context::findvalues (CWE-643) ---

func TestRust_Libxml_Findvalues(t *testing.T) {
	code := `
use std::env;
use libxml::parser::Parser;
use libxml::xpath::Context;

fn handle() {
    let expr = env::var("XPATH").unwrap();
    let parser = Parser::default();
    let doc = parser.parse_string("<a/>").unwrap();
    let ctx = Context::new(&doc).unwrap();
    let vs = ctx.findvalues(&expr, None);
}
`
	flows := Analyze(code, "/app/xml.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath flow for env::var -> libxml Context::findvalues")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- amxml: NodePtr::eval_xpath (CWE-643) ---

func TestRust_Amxml_EvalXpath(t *testing.T) {
	code := `
use std::env;
use amxml::dom::new_document;

fn handle() {
    let expr = env::var("XPATH").unwrap();
    let doc = new_document("<a/>").unwrap();
    doc.eval_xpath(&expr);
}
`
	flows := Analyze(code, "/app/xml.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Errorf("expected XPath flow for env::var -> amxml NodePtr::eval_xpath; got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Safe: hardcoded libxml XPath (should NOT flag) ---

func TestRust_Libxml_Safe_Hardcoded(t *testing.T) {
	code := `
use libxml::parser::Parser;
use libxml::xpath::Context;

fn handle() {
    let parser = Parser::default();
    let doc = parser.parse_string("<a/>").unwrap();
    let ctx = Context::new(&doc).unwrap();
    let nodes = ctx.findnodes("//book/title", None);
}
`
	flows := Analyze(code, "/app/xml.rs", rules.LangRust)
	if hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("hardcoded libxml XPath should not produce XPath flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
