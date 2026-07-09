package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// hasTemplateFormatInjectionFlow reports whether any CWE-1336 format-string
// injection flow (string.Template/format_map family) reached a sink at the
// given line.
func hasTemplateFormatInjectionFlow(flows []taint.TaintFlow, line int) bool {
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTemplate && f.Sink.CWEID == "CWE-1336" && f.SinkLine == line {
			return true
		}
	}
	return false
}

// TestPython_FormatStringInjection_PayloadReceiver exercises the PayloadPosition
// repositioning of the py.string.template.substitute / py.string.template.ctor
// sinks (CWE-1336). The dangerous payload of str.format_map / .substitute /
// .safe_substitute is the TEMPLATE (the receiver), not the mapping argument
// (which holds substituted values). string.Template(TEMPLATE) is the converse:
// its template is the constructor argument.
//
// THE false-positive gate (FP_constTemplate_taintedMapping) is the load-bearing
// case: on the pre-change baseline (single sink, DangerousArgs:[0] pointing at
// the mapping) it FALSE-fires; after the PayloadReceiver reposition it is
// correctly suppressed. See the fail-then-pass note below.
func TestPython_FormatStringInjection_PayloadReceiver(t *testing.T) {
	t.Run("vulnerable", func(t *testing.T) {
		cases := []struct {
			name string
			code string
			line int
		}{
			{
				// Tainted template flows into format_map as the RECEIVER.
				name: "format_map_tainted_template_receiver",
				code: "t = request.args['x']\nt.format_map(d)\n",
				line: 2,
			},
			{
				name: "safe_substitute_tainted_template_receiver",
				code: "t = request.args['x']\nt.safe_substitute(d)\n",
				line: 2,
			},
			{
				// Receiver name that prefix-matches the ObjectType, tainted.
				name: "template_named_tainted_receiver",
				code: "template = request.args['x']\ntemplate.format_map(d)\n",
				line: 2,
			},
			{
				// string.Template(TAINTED).substitute(x): the template is the
				// constructor argument — fires via py.string.template.ctor.
				name: "Template_ctor_chained_tainted_template",
				code: "string.Template(request.args['t']).substitute(x)\n",
				line: 1,
			},
			{
				// Two-step constructor: fires on the constructor line.
				name: "Template_ctor_twostep_tainted_template",
				code: "tpl = string.Template(request.args['t'])\ntpl.substitute(x)\n",
				line: 1,
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				flows := Analyze(tc.code, "/app/h.py", rules.LangPython)
				if !hasTemplateFormatInjectionFlow(flows, tc.line) {
					t.Errorf("expected CWE-1336 format-string injection flow at line %d for %s", tc.line, tc.name)
					for _, f := range flows {
						t.Logf("  flow: src=%s sink=%s id=%s cwe=%s srcLine=%d sinkLine=%d",
							f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID, f.SourceLine, f.SinkLine)
					}
				}
			})
		}
	})

	t.Run("safe", func(t *testing.T) {
		cases := []struct {
			name string
			code string
			line int
		}{
			{
				// CONSTANT template + tainted MAPPING: the mapping holds
				// substituted values, which are safe under a constant template.
				// This is THE false positive the reposition removes — on baseline
				// (DangerousArgs:[0] = mapping) it fires; after PayloadReceiver it
				// must not. The receiver name `template` prefix-matches the sink
				// ObjectType "string.Template" so the call structurally matches.
				name: "FP_constTemplate_taintedMapping",
				code: "template = '{n}'\nd = request.args['x']\ntemplate.format_map(d)\n",
				line: 3,
			},
			{
				// Literal const template directly, tainted mapping.
				name: "FP_constLiteralTemplate_taintedMappingSource",
				code: "'{n}'.format_map(request.args)\n",
				line: 1,
			},
			{
				// Constant template into string.Template, tainted mapping into
				// substitute: neither the ctor arg nor the substitute receiver is
				// tainted.
				name: "FP_Template_constTemplate_taintedMapping",
				code: "string.Template('const').substitute(request.args)\n",
				line: 1,
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				flows := Analyze(tc.code, "/app/h.py", rules.LangPython)
				if hasTemplateFormatInjectionFlow(flows, tc.line) {
					t.Errorf("FALSE POSITIVE: CWE-1336 format-string injection flow at line %d for %s", tc.line, tc.name)
					for _, f := range flows {
						t.Logf("  flow: src=%s sink=%s id=%s cwe=%s srcLine=%d sinkLine=%d",
							f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID, f.SourceLine, f.SinkLine)
					}
				}
			})
		}
	})
}

// TestPayloadPosition_DefaultZeroIsNoOp documents the #1259 guardrail: the
// zero value PayloadDefault is the historical behavior. A sink that never sets
// PayloadPosition runs the dangerous-arg loop with the receiver fallback, so an
// argument-payload sink (here a plain command-exec source-at-sink) still fires
// exactly as before.
func TestPayloadPosition_DefaultZeroIsNoOp(t *testing.T) {
	// os.system(tainted) — arg-payload sink, default PayloadPosition.
	code := "import os\ncmd = request.args['c']\nos.system(cmd)\n"
	flows := Analyze(code, "/app/h.py", rules.LangPython)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand && f.SinkLine == 3 {
			found = true
		}
	}
	if !found {
		t.Error("expected default-zero arg-payload command-exec flow to fire unchanged")
	}
}
