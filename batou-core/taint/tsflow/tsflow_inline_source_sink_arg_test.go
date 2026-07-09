package tsflow

// Inline-source-in-wrapper-call at sink-argument position (Strategy Board:
// "inline _.merge(t, req.X) recall gap").
//
// The var-assigned twin of each shape below already produced a flow
// (assignment-position resolution walks a wrapper call's arguments via
// matchSanitizer + resolveInlineSourceThroughSanitizer, or
// propagateCallResultInterproc → resolveUnpackElemTaint). The INLINE twin was
// dataflow-invisible because findSourceInExpr never descends into a call's
// ARGUMENTS (only its receiver chain), and the sink-arg inline-synthesis
// fallback in emitInterprocSinkFlows had no wrapper-call branch. These tests
// pin the fix (resolveInlineSourceThroughCallArgs) and its guards:
//
//   - sanitizer wrappers still neutralise (`_.merge(t, sjson.parse(req.body))`)
//   - the #1301 SrcDatabase→SnkPrototype gate in addFlow still applies
//     (`_.merge(t, wrap(...))` reading a DB doc must not fire)
//   - direct inline member-expr sources (`_.merge(t, req.body)`,
//     `exec(req.body.cmd)`) keep firing at confidence 1.0 (pre-existing
//     behaviour, shipped in #1014)

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

func findFlowForSink(flows []taint.TaintFlow, cat taint.SinkCategory) (taint.TaintFlow, bool) {
	for _, f := range flows {
		if f.Sink.Category == cat {
			return f, true
		}
	}
	return taint.TaintFlow{}, false
}

// TestInlineSinkArg_MergeReqBody_Direct pins the pre-existing direct form:
// an inline member-expression source as the sink argument fires at full
// confidence with the right CWE.
func TestInlineSinkArg_MergeReqBody_Direct(t *testing.T) {
	code := `
const _ = require('lodash');
function handler(req, res) {
    _.merge(target, req.body);
    return res.json(target);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	f, ok := findFlowForSink(flows, taint.SnkPrototype)
	if !ok {
		t.Fatal("inline _.merge(target, req.body) must produce a prototype-pollution flow, got none")
	}
	if f.Sink.CWEID != "CWE-1321" {
		t.Errorf("expected CWE-1321, got %s", f.Sink.CWEID)
	}
	if f.Source.Category != taint.SrcUserInput {
		t.Errorf("expected SrcUserInput source, got %s", f.Source.Category)
	}
	if f.Confidence < 1.0 {
		t.Errorf("direct inline member-expr source must keep confidence 1.0, got %.2f", f.Confidence)
	}
}

// TestInlineSinkArg_ObjectAssignReqQuery_Direct covers the Object.assign
// sibling sink with a different request field.
func TestInlineSinkArg_ObjectAssignReqQuery_Direct(t *testing.T) {
	code := `
function handler(req, res) {
    Object.assign(target, req.query);
    return res.json(target);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	f, ok := findFlowForSink(flows, taint.SnkPrototype)
	if !ok {
		t.Fatal("inline Object.assign(target, req.query) must produce a prototype-pollution flow, got none")
	}
	if f.Sink.CWEID != "CWE-1321" {
		t.Errorf("expected CWE-1321, got %s", f.Sink.CWEID)
	}
}

// TestInlineSinkArg_MergeJSONParseReqBody_WrapperCall is THE recall fix: the
// member-expr source sits inside a neutral wrapper call at the sink argument.
// The var-assigned twin (`const src = JSON.parse(req.body.data); _.merge(...)`)
// already fired; the inline twin produced no flow before
// resolveInlineSourceThroughCallArgs.
func TestInlineSinkArg_MergeJSONParseReqBody_WrapperCall(t *testing.T) {
	code := `
const _ = require('lodash');
function handler(req, res) {
    _.merge(target, JSON.parse(req.body.data));
    return res.json(target);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	f, ok := findFlowForSink(flows, taint.SnkPrototype)
	if !ok {
		t.Fatal("inline _.merge(target, JSON.parse(req.body.data)) must produce a prototype-pollution flow, got none")
	}
	if f.Sink.CWEID != "CWE-1321" {
		t.Errorf("expected CWE-1321, got %s", f.Sink.CWEID)
	}
	if f.Source.Category != taint.SrcUserInput {
		t.Errorf("expected SrcUserInput source, got %s", f.Source.Category)
	}
}

// TestInlineSinkArg_SanitizedInline_NoFlow: a registered prototype-pollution
// sanitizer (secure-json-parse) wrapping the inline source must suppress the
// flow — same sanitizer interaction the assignment position has.
func TestInlineSinkArg_SanitizedInline_NoFlow(t *testing.T) {
	code := `
const _ = require('lodash');
const sjson = require('secure-json-parse');
function handler(req, res) {
    _.merge(target, sjson.parse(req.body.data));
    return res.json(target);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if f, ok := findFlowForSink(flows, taint.SnkPrototype); ok {
		t.Errorf("sanitized inline source must not fire, got flow source=%s conf=%.2f", f.Source.ID, f.Confidence)
	}
}

// TestInlineSinkArg_InlineDBSource_GateHolds extends the #1301 precision gate
// to the inline shape: a DB read (SrcDatabase) as a direct inline sink arg
// must NOT produce a prototype-pollution flow — a DB document's key namespace
// is the schema, not attacker-controlled.
func TestInlineSinkArg_InlineDBSource_GateHolds(t *testing.T) {
	code := `
const _ = require('lodash');
async function handler(req, res) {
    _.merge(target, await Model.findOne({ id: req.params.id }));
    return res.json(target);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if f, ok := findFlowForSink(flows, taint.SnkPrototype); ok {
		t.Errorf("inline DB-sourced prototype pollution must be suppressed (#1301 gate), got source=%s (%s)",
			f.Source.Category, f.Source.ID)
	}
}

// TestInlineSinkArg_InlineDBSource_NoAwait_GateHolds covers the same gate for
// the synchronous inline form.
func TestInlineSinkArg_InlineDBSource_NoAwait_GateHolds(t *testing.T) {
	code := `
const _ = require('lodash');
function handler(req, res) {
    _.merge(target, model.findOne({ id: req.params.id }));
    return res.json(target);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if f, ok := findFlowForSink(flows, taint.SnkPrototype); ok {
		t.Errorf("inline DB-sourced prototype pollution must be suppressed (#1301 gate), got source=%s (%s)",
			f.Source.Category, f.Source.ID)
	}
}

// TestInlineSinkArg_ExecReqBodyCmd_Control is the non-proto control: the
// direct inline member-expr form for a command sink flowed before this change
// and must be unchanged (CWE-78, confidence 1.0).
func TestInlineSinkArg_ExecReqBodyCmd_Control(t *testing.T) {
	code := `
const { exec } = require('child_process');
function handler(req, res) {
    exec(req.body.cmd);
    return res.sendStatus(200);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	f, ok := findFlowForSink(flows, taint.SnkCommand)
	if !ok {
		t.Fatal("inline exec(req.body.cmd) must produce a command-injection flow, got none")
	}
	if f.Confidence < 1.0 {
		t.Errorf("direct inline member-expr source must keep confidence 1.0, got %.2f", f.Confidence)
	}
}

// TestInlineSinkArg_ExecWrappedReqBody_RecallExpansion documents the recall
// expansion beyond the prototype category: an unknown wrapper call around the
// inline source now flows for command sinks too, at the same one-hop
// propagation decay (0.85) its var-assigned twin gets.
func TestInlineSinkArg_ExecWrappedReqBody_RecallExpansion(t *testing.T) {
	code := `
const { exec } = require('child_process');
function handler(req, res) {
    exec(buildCommand(req.body.cmd));
    return res.sendStatus(200);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	f, ok := findFlowForSink(flows, taint.SnkCommand)
	if !ok {
		t.Fatal("inline exec(buildCommand(req.body.cmd)) must produce a command-injection flow, got none")
	}
	if f.Confidence > 0.85+1e-9 || f.Confidence < 0.85-1e-9 {
		t.Errorf("unknown-wrapper inline source must carry one-hop propagation decay 0.85, got %.2f", f.Confidence)
	}
}

// TestInlineSinkArg_PythonWrappedSource_CrossLanguage verifies the fix comes
// for free through the shared walker in other language configs: a Python
// command sink with the request source wrapped in an unknown helper call.
func TestInlineSinkArg_PythonWrappedSource_CrossLanguage(t *testing.T) {
	code := `
import os
from flask import request

def handler():
    os.system(build_cmd(request.args.get("c")))
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if _, ok := findFlowForSink(flows, taint.SnkCommand); !ok {
		t.Fatal("inline os.system(build_cmd(request.args.get(\"c\"))) must produce a command-injection flow, got none")
	}
}

// TestInlineSinkArg_LiteralWrapperArg_NoFlow: a wrapper call whose arguments
// carry no source must stay clean — the mechanism only seeds from resolved
// source defs, never from the mere presence of a call.
func TestInlineSinkArg_LiteralWrapperArg_NoFlow(t *testing.T) {
	code := `
const _ = require('lodash');
function handler(req, res) {
    _.merge(target, loadDefaults("config.json"));
    return res.json(target);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if f, ok := findFlowForSink(flows, taint.SnkPrototype); ok {
		t.Errorf("wrapper over a literal must not fire, got flow source=%s", f.Source.ID)
	}
}
