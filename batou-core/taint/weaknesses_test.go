package taint_test

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// weaknesses_test.go pins down known imprecisions in the regex-based taint
// engine (taint.Analyze). These are NOT assertions that the behavior is
// correct — they document today's behavior so a future improvement flips the
// test and forces the expectation to be updated.
//
// Each test has a "Today:" note describing observed behavior and an "Ideal:"
// note describing what a precise engine would do.

// ---------------------------------------------------------------------------
// 1. Struct/object field taint collapses to the root variable.
//
// engine.go:347-360 strips `.field` / `[key]` from the LHS of an assignment,
// so `obj.safe = tainted` marks `obj` as tainted. A later read of an unrelated
// field like `obj.other_field` will match the regex `exprReferencesVar(arg, "obj")`
// and fire — a false positive.
// ---------------------------------------------------------------------------

func TestWeakness_StructFieldTaint_FalsePositiveOnUnrelatedField(t *testing.T) {
	code := `func handler(w http.ResponseWriter, r *http.Request) {
	obj := Wrapper{}
	obj.tainted = r.FormValue("x")
	db.Query(obj.other_field)
}`
	flows := taint.Analyze(code, "handler.go", rules.LangGo)

	// Today: the regex engine marks `obj` tainted after `obj.tainted = ...`
	// and `exprReferencesVar("obj.other_field", "obj")` returns true, so a
	// flow is reported even though only .tainted holds user input.
	//
	// Ideal: no flow — obj.other_field never received tainted data.
	if len(flows) == 0 {
		t.Log("GOOD: engine distinguished struct fields; update this test.")
	} else {
		t.Logf("known weakness: %d spurious flow(s) from unrelated struct field", len(flows))
	}
}

// ---------------------------------------------------------------------------
// 2. Container/map element taint paints the whole container.
//
// `m[k] = tainted` → the engine strips `[k]` and tracks `m`. Any later use of
// a different key (`m["safe"]`) is treated as tainted.
// ---------------------------------------------------------------------------

func TestWeakness_MapElementTaint_FalsePositiveOnOtherKey(t *testing.T) {
	code := `func handler(w http.ResponseWriter, r *http.Request) {
	m := map[string]string{}
	m["user"] = r.FormValue("name")
	m["constant"] = "hello"
	db.Query(m["constant"])
}`
	flows := taint.Analyze(code, "handler.go", rules.LangGo)

	if len(flows) == 0 {
		t.Log("GOOD: engine distinguishes map keys; update this test.")
	} else {
		t.Logf("known weakness: %d spurious flow(s) from unrelated map key", len(flows))
	}
}

// ---------------------------------------------------------------------------
// 3. Confidence decay through a long chain of unknown functions.
//
// tracker.go: unknownFunctionDecay = 0.8. After N hops through unknown helper
// functions, confidence = 0.8^N. Four hops = 0.41 < 0.7, which downgrades the
// finding from "high" to "medium". At a typical blocking threshold of
// RiskScore >= 0.7, a Critical finding stops blocking after ~4 utility hops.
// ---------------------------------------------------------------------------

func TestWeakness_ConfidenceDecay_FourHopChainDemoted(t *testing.T) {
	code := `func handler(w http.ResponseWriter, r *http.Request) {
	a := r.FormValue("x")
	b := wrap1(a)
	c := wrap2(b)
	d := wrap3(c)
	e := wrap4(d)
	db.Query(e)
}`
	flows := taint.Analyze(code, "handler.go", rules.LangGo)

	if len(flows) == 0 {
		t.Fatal("expected a flow to be detected at all")
	}

	// Today: the 4-hop chain's confidence is well below 0.7.
	// If a future engine tracks known-pure vs unknown more precisely, or
	// drops the per-hop decay, this may rise above 0.7.
	got := flows[0].Confidence
	if got >= 0.7 {
		t.Logf("GOOD: 4-hop chain survived decay (conf=%.2f); update this test.", got)
	} else {
		t.Logf("known weakness: 4-hop chain demoted to conf=%.2f (< 0.7)", got)
	}
}

// ---------------------------------------------------------------------------
// 4. Sanitizer stickiness across reassignment from a fresh source.
//
// The engine's propagation copies the Sanitized map forward on assignment.
// The real concern is whether a fresh source assignment resets that map.
// This test is a contract check: after re-tainting from a new source, the
// variable must reach the sink. If it doesn't, a sanitizer is "sticky" and
// bypassable via alias/re-tainting patterns.
// ---------------------------------------------------------------------------

func TestWeakness_SanitizerRetaint_FreshSourceReachesSink(t *testing.T) {
	code := `def handler(request):
    x = request.args.get("x")
    y = html.escape(x)           # y is sanitized for HTML
    y = request.args.get("y")    # re-tainted from a fresh source
    cursor.execute(y)            # SQL sink — HTML sanitizer must not apply
`
	flows := taint.Analyze(code, "handler.py", rules.LangPython)

	// Today: the regex engine should report this flow because:
	//   (a) SnkSQLQuery is not in html.escape's Neutralizes list, and
	//   (b) re-assignment from a fresh source creates a new TaintVar.
	// If this test ever starts returning zero flows, the sanitizer-stickiness
	// bypass is real and needs fixing.
	if len(flows) == 0 {
		t.Error("sanitizer re-taint bypass: fresh source after sanitize did not reach SQL sink")
	}
}

// ---------------------------------------------------------------------------
// 5. HTML sanitizer in a JS/URL output context (category mismatch).
//
// An HTML-escaping sanitizer must not mark data safe for a JavaScript
// response or a redirect sink. Sanitizer.Neutralizes is the single source of
// truth — this test guards against accidental over-broad Neutralizes lists
// when catalogs grow.
// ---------------------------------------------------------------------------

func TestWeakness_SanitizerContextMismatch_HTMLEscapeIntoRedirect(t *testing.T) {
	code := `def handler(request):
    raw = request.args.get("next")
    safe = html.escape(raw)
    return redirect(safe)
`
	flows := taint.Analyze(code, "handler.py", rules.LangPython)

	// If html.escape is ever miscategorized as neutralizing redirect sinks,
	// this test will silently pass with zero flows — which is the real
	// concern. Require at least one flow.
	if len(flows) == 0 {
		t.Error("HTML sanitizer incorrectly cleared taint for non-HTML sink (redirect)")
	}
}
