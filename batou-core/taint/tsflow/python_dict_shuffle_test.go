package tsflow

// Python strong-update (last-write-wins) for the OWASP dict/list-shuffle SAFE
// pattern. These verify the gate added in processAssignInterproc /
// isUnconditionalAssign:
//
//   - Two UNCONDITIONAL sibling assignments `bar = map['keyB'] (tainted);
//     bar = map['keyA'] (constant)` → the final constant write clears taint
//     (no flow). This is the FP that OWASP deser/xpathi/ldapi/codeinj/
//     pathtraver SAFE cases exhibit.
//   - The same shape but ending in the TAINTED key still flows (TP guard).
//   - match-statement arms (CONDITIONAL) must NOT be cleared by a later
//     all-literal arm — the documented hazard the gate intentionally avoids.

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Negative: dict-shuffle ending in the SAFE key clears taint (deserialize).
func TestPython_DictShuffle_LastKeyA_NoFlow(t *testing.T) {
	code := `
from flask import request
import pickle, base64

def handler():
    param = request.form.get('p')
    m = {}
    m['keyA'] = 'a-Value'
    m['keyB'] = param
    bar = "safe!"
    bar = m['keyB']
    bar = m['keyA']
    unpickled = pickle.loads(base64.urlsafe_b64decode(bar))
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Errorf("dict-shuffle ending in safe key m['keyA'] should NOT flow to pickle.loads")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// Positive (TPR guard): the same shape but the LAST unconditional write reads
// the TAINTED key — taint must survive to the sink.
func TestPython_DictShuffle_LastKeyB_Flows(t *testing.T) {
	code := `
from flask import request
import pickle, base64

def handler():
    param = request.form.get('p')
    m = {}
    m['keyA'] = 'a-Value'
    m['keyB'] = param
    bar = "safe!"
    bar = m['keyA']
    bar = m['keyB']
    unpickled = pickle.loads(base64.urlsafe_b64decode(bar))
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Errorf("dict-shuffle ending in tainted key m['keyB'] MUST flow to pickle.loads")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// Positive (TPR guard, the documented hazard): match-statement with a tainted
// arm followed by an all-literal arm — the literal arm is CONDITIONAL and must
// NOT clear the tainted arm. This is an XPath sink (OWASP xpathi shape).
func TestPython_MatchArm_TaintedThenLiteral_Flows(t *testing.T) {
	code := `
from flask import request
from lxml import etree

def handler(doc):
    param = request.form.get('p')
    match guess:
        case 'A':
            bar = param
        case 'B':
            bar = 'bob'
        case _:
            bar = 'uncle'
    doc.xpath("/users/user[@name='" + bar + "']")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Errorf("match arm `bar = param` must survive a later literal arm and flow to xpath")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// Negative: a tainted assignment inside an `if` (CONDITIONAL) followed by an
// UNCONDITIONAL literal write — the prior taint was set conditionally so it is
// NOT eligible for the strong-update clear, but the branch-merge already keeps
// it; the later literal write is unconditional. The gate must not clear a
// conditionally-set taint (prior.setUnconditionally == false), so this still
// flows (conservative — matches pre-fix may-be-tainted semantics).
func TestPython_CondTaintThenUncondLiteral_StillFlows(t *testing.T) {
	code := `
from flask import request
import pickle, base64

def handler(cond):
    param = request.form.get('p')
    bar = "safe"
    if cond:
        bar = param
    bar2 = bar
    unpickled = pickle.loads(base64.urlsafe_b64decode(bar2))
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Errorf("conditionally-tainted bar must still flow (no unconditional clear applies)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}
