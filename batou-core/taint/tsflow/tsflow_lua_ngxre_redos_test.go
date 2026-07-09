package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Lua — OpenResty ngx.re ReDoS sink family completion (CWE-1333)
//
// ngx.re.match/gmatch were already modeled; find/gsub/sub run the same
// backtracking PCRE engine with the regex at arg index 1 and were silent
// ReDoS false negatives. A tainted *pattern* must fire; a tainted *subject*
// (arg 0, the normal place for untrusted data) must not.
// =========================================================================

func TestLua_NgxRe_Find_TaintedPattern_ReDoS(t *testing.T) {
	code := `
function handler()
    local patt = ngx.req.get_uri_args()["pattern"]
    local from, to = ngx.re.find("some subject", patt, "jo")
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkRegexDoS) {
		t.Error("expected ReDoS flow for tainted pattern -> ngx.re.find (arg 1)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_NgxRe_Gsub_TaintedPattern_ReDoS(t *testing.T) {
	code := `
function handler()
    local patt = ngx.req.get_uri_args()["pattern"]
    local out = ngx.re.gsub("some subject", patt, "X", "jo")
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkRegexDoS) {
		t.Error("expected ReDoS flow for tainted pattern -> ngx.re.gsub (arg 1)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_NgxRe_Sub_TaintedPattern_ReDoS(t *testing.T) {
	code := `
function handler()
    local patt = ngx.req.get_uri_args()["pattern"]
    local out = ngx.re.sub("some subject", patt, "X", "jo")
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkRegexDoS) {
		t.Error("expected ReDoS flow for tainted pattern -> ngx.re.sub (arg 1)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative control: a tainted *subject* (arg 0) with a constant literal pattern
// is the normal, safe use of these functions — scanning untrusted data against a
// fixed expression — and must NOT raise a ReDoS finding. This also guards the
// coexistence of the ngx.re.gsub/sub sanitizer entries (which key on the subject).
func TestLua_NgxRe_ConstantPattern_NoReDoS(t *testing.T) {
	code := `
function handler()
    local subject = ngx.req.get_uri_args()["q"]
    local from, to = ngx.re.find(subject, "[0-9]+", "jo")
    local g = ngx.re.gsub(subject, "[\r\n]", "", "jo")
    local s = ngx.re.sub(subject, "[\\x00-\\x1f]", "", "jo")
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if hasTaintFlow(flows, taint.SnkRegexDoS) {
		t.Error("did NOT expect a ReDoS flow when the pattern is a constant literal (subject taint is the normal, safe case)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
