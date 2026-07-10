package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// TestRust_MinijinjaRenderStr verifies SSTI detection for env.render_str()
// when the template source comes from user input.
func TestRust_MinijinjaRenderStr(t *testing.T) {
	code := `
use std::env;
use minijinja::{context, Environment};

fn handler() -> String {
    let user_template = env::var("TPL").unwrap();
    let env = Environment::new();
    env.render_str(&user_template, context!{ name => "World" }).unwrap()
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTemplate && f.Sink.ID == "rust.minijinja.render_str" {
			found = true
		}
	}
	if !found {
		t.Error("expected SnkTemplate flow for env.render_str(user_template)")
		for _, f := range flows {
			t.Logf("  flow: src=%s sink=%s (cat=%s)", f.Source.ID, f.Sink.ID, f.Sink.Category)
		}
	}
}

// TestRust_MinijinjaRenderNamedStr verifies SSTI detection for the
// render_named_str variant where the template source is the second argument.
func TestRust_MinijinjaRenderNamedStr(t *testing.T) {
	code := `
use std::env;
use minijinja::{context, Environment};

fn handler() -> String {
    let user_template = env::var("TPL").unwrap();
    let env = Environment::new();
    env.render_named_str("page", &user_template, context!{ name => "World" }).unwrap()
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTemplate && f.Sink.ID == "rust.minijinja.render_named_str" {
			found = true
		}
	}
	if !found {
		t.Error("expected SnkTemplate flow for env.render_named_str(name, user_template, ctx)")
		for _, f := range flows {
			t.Logf("  flow: src=%s sink=%s (cat=%s)", f.Source.ID, f.Sink.ID, f.Sink.Category)
		}
	}
}

// TestRust_MinijinjaTemplateFromStr verifies SSTI detection for
// template_from_str() which compiles a template from a (possibly tainted) string.
func TestRust_MinijinjaTemplateFromStr(t *testing.T) {
	code := `
use std::env;
use minijinja::{context, Environment};

fn handler() -> String {
    let user_template = env::var("TPL").unwrap();
    let env = Environment::new();
    let tmpl = env.template_from_str(&user_template).unwrap();
    tmpl.render(context!{ name => "World" }).unwrap()
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTemplate && f.Sink.ID == "rust.minijinja.template_from_str" {
			found = true
		}
	}
	if !found {
		t.Error("expected SnkTemplate flow for env.template_from_str(user_template)")
		for _, f := range flows {
			t.Logf("  flow: src=%s sink=%s (cat=%s)", f.Source.ID, f.Sink.ID, f.Sink.Category)
		}
	}
}

// TestRust_MinijinjaAddTemplate verifies SSTI detection for env.add_template
// when the template body (second argument) is user-controlled.
func TestRust_MinijinjaAddTemplate(t *testing.T) {
	code := `
use std::env;
use minijinja::{context, Environment};

fn handler() -> String {
    let user_template = env::var("TPL").unwrap();
    let mut env = Environment::new();
    env.add_template("page", &user_template).unwrap();
    let tmpl = env.get_template("page").unwrap();
    tmpl.render(context!{ name => "World" }).unwrap()
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTemplate && f.Sink.ID == "rust.minijinja.add_template" {
			found = true
		}
	}
	if !found {
		t.Error("expected SnkTemplate flow for env.add_template(name, user_template)")
		for _, f := range flows {
			t.Logf("  flow: src=%s sink=%s (cat=%s)", f.Source.ID, f.Sink.ID, f.Sink.Category)
		}
	}
}

// TestRust_MinijinjaSafe_HardcodedTemplate verifies that a hardcoded template
// string with only the context tainted does NOT produce an SSTI finding —
// minijinja escapes context values by default; only the template source is
// the SSTI vector.
func TestRust_MinijinjaSafe_HardcodedTemplate(t *testing.T) {
	code := `
use std::env;
use minijinja::{context, Environment};

fn handler() -> String {
    let user_name = env::var("NAME").unwrap();
    let env = Environment::new();
    env.render_str("Hello {{ name }}!", context!{ name => user_name }).unwrap()
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTemplate && f.Sink.ID == "rust.minijinja.render_str" {
			t.Errorf("unexpected SSTI flow for hardcoded template literal: src=%s", f.Source.ID)
		}
	}
}
