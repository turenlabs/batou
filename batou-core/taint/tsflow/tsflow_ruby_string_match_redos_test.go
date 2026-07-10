package tsflow

// Ruby — String#match / String#match? ReDoS (CWE-1333).
//
// String#match and String#match? implicitly compile a String argument into a
// Regexp ("foo".match(p) ≡ Regexp.new(p).match("foo")), with regexp
// metacharacters ACTIVE. So a tainted *pattern* argument enables catastrophic
// backtracking in Ruby's Onigmo engine (ReDoS). This complements the existing
// ruby.regexp.new sink, which only covers explicit Regexp.new/Regexp.compile.
//
// The sink is scoped to ObjectType "String" so DangerousArgs[0] is the
// pattern; Regexp#match takes the haystack at arg 0 (the opposite) and is not
// matched. The haystack/receiver is never the dangerous argument.

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Positive: a request-derived pattern flowing into String#match must fire a
// SnkRegexDoS flow (and specifically the new ruby.string.match sink).
func TestRuby_StringMatch_ReDoS_Vulnerable(t *testing.T) {
	code := `
def search(params)
  pattern = params[:q]
  str = "haystack to scan"
  str.match(pattern)
end
`
	flows := Analyze(code, "/app/controllers/search_controller.rb", rules.LangRuby)
	if !hasFlowFromSink(flows, "ruby.string.match", taint.SnkRegexDoS) {
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
		t.Fatalf("expected SnkRegexDoS flow (ruby.string.match) for params[:q] -> str.match(pattern); got %d flows", len(flows))
	}
}

// Positive: String#match? (predicate form) is also covered by the compound
// MethodName "match/match?".
func TestRuby_StringMatchPredicate_ReDoS_Vulnerable(t *testing.T) {
	code := `
def valid?(params)
  rule = params[:pattern]
  str = "candidate value"
  str.match?(rule)
end
`
	flows := Analyze(code, "/app/controllers/rules_controller.rb", rules.LangRuby)
	if !hasFlowFromSink(flows, "ruby.string.match", taint.SnkRegexDoS) {
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
		t.Fatalf("expected SnkRegexDoS flow (ruby.string.match) for params[:pattern] -> str.match?(rule); got %d flows", len(flows))
	}
}

// Negative: a constant/literal regex pattern must NOT fire even when the
// haystack receiver is tainted — DangerousArgs[0] keys on the pattern arg, not
// the receiver. This proves the haystack is never the dangerous argument.
func TestRuby_StringMatch_ReDoS_ConstantPattern_NoFlow(t *testing.T) {
	code := `
def search(params)
  str = params[:q]
  str.match(/[a-z]+/)
end
`
	flows := Analyze(code, "/app/controllers/search_controller.rb", rules.LangRuby)
	if hasFlowFromSink(flows, "ruby.string.match", taint.SnkRegexDoS) {
		t.Fatalf("constant regex literal /[a-z]+/ must NOT fire ruby.string.match (tainted receiver/haystack is not the dangerous argument)")
	}
}
