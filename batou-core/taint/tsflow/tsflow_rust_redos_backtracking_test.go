package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// --- ReDoS via third-party BACKTRACKING regex engines (CWE-1333) ---
//
// The std `regex` crate is finite-automata (linear-time, immune to
// catastrophic backtracking). fancy-regex, onig (Oniguruma) and pcre2 wrap
// backtracking engines to support look-around/backreferences, so a tainted
// pattern can trigger exponential catastrophic backtracking (classic ReDoS).
// The qualified crate path in ObjectType keeps these distinct from the std
// regex::Regex entry.

func TestRust_ReDoS_FancyRegex_New(t *testing.T) {
	code := `
use std::env;
use fancy_regex;

fn handler() {
    let pattern = env::var("USER_PATTERN").unwrap();
    let re = fancy_regex::Regex::new(&pattern);
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkRegexDoS) {
		t.Error("expected ReDoS flow for env::var -> fancy_regex::Regex::new (backtracking engine)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_ReDoS_FancyRegex_Builder(t *testing.T) {
	code := `
use std::env;
use fancy_regex;

fn handler() {
    let pattern = env::var("USER_PATTERN").unwrap();
    let re = fancy_regex::RegexBuilder::new(&pattern).build().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkRegexDoS) {
		t.Error("expected ReDoS flow for env::var -> fancy_regex::RegexBuilder::new (backtracking engine)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_ReDoS_Onig_New(t *testing.T) {
	code := `
use std::env;
use onig;

fn handler() {
    let pattern = env::var("USER_PATTERN").unwrap();
    let re = onig::Regex::new(&pattern);
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkRegexDoS) {
		t.Error("expected ReDoS flow for env::var -> onig::Regex::new (Oniguruma backtracking engine)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_ReDoS_Pcre2_New(t *testing.T) {
	code := `
use std::env;
use pcre2;

fn handler() {
    let pattern = env::var("USER_PATTERN").unwrap();
    let re = pcre2::bytes::Regex::new(&pattern);
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkRegexDoS) {
		t.Error("expected ReDoS flow for env::var -> pcre2::bytes::Regex::new (PCRE2 backtracking engine)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// FP-safety: the qualified-path ObjectType must scope these to the regex
// crates only — a same-named `new` constructor on an unrelated type fed the
// same tainted value must NOT be reported as ReDoS.
func TestRust_ReDoS_NonRegexConstructor_NoFlow(t *testing.T) {
	code := `
use std::env;

fn handler() {
    let pattern = env::var("USER_PATTERN").unwrap();
    let widget = my_crate::Widget::new(&pattern);
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRegexDoS {
			t.Error("a non-regex ::new() constructor must not produce a ReDoS flow")
		}
	}
}

// Negative control: a constant (non-tainted) pattern is not a ReDoS flow.
func TestRust_ReDoS_FancyRegex_Constant_NoFlow(t *testing.T) {
	code := `
use fancy_regex;

fn handler() {
    let re = fancy_regex::Regex::new("(a+)+$");
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRegexDoS {
			t.Error("constant pattern with no tainted source must not produce a ReDoS flow")
		}
	}
}
