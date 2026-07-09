package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// hasSinkFlow reports whether any flow reached a sink with the given catalog ID
// at the given line.
func hasSinkFlow(flows []taint.TaintFlow, sinkID string, line int) bool {
	for _, f := range flows {
		if f.Sink.ID == sinkID && f.SinkLine == line {
			return true
		}
	}
	return false
}

// TestConstrainedName_ReflectiveSinks exercises SLICE 4: the Python getattr
// CWE-470 reflection sink plus the constrained-name recogniser that hardens both
// getattr and setattr against the pervasive SAFE framework idioms.
//
// THE two load-bearing FAIL-then-PASS cases:
//   - getattr-fire (vulnerable/getattr_request_args): revert ONLY the
//     py.getattr.reflection sink in python_sinks.go and this case FAILS (no
//     sink); restore → PASS.
//   - constrained-suppression (safe/getattr_request_method_lower): revert ONLY
//     constrained_name.go + the walker RejectConstrainedName gate and this case
//     FAILS (request.method.lower() FP-fires as an inline request source);
//     restore → PASS.
func TestConstrainedName_ReflectiveSinks(t *testing.T) {
	t.Run("vulnerable", func(t *testing.T) {
		cases := []struct {
			name   string
			code   string
			sinkID string
			line   int
		}{
			{
				// OPEN attacker-controlled name → unsafe reflection (CWE-470).
				// FAIL-then-PASS anchor for the getattr sink itself.
				name:   "getattr_request_args",
				code:   "def h(obj):\n    return getattr(obj, request.args['x'])\n",
				sinkID: "py.getattr.reflection",
				line:   2,
			},
			{
				// Tainted name flowing through a variable into getattr.
				name:   "getattr_tainted_var",
				code:   "def h(obj):\n    name = request.form['f']\n    return getattr(obj, name)\n",
				sinkID: "py.getattr.reflection",
				line:   3,
			},
			{
				// setattr mass-assignment with a tainted name (CWE-915). Routed
				// through a variable because py.setattr.massassign is a
				// SnkTrustBoundary sink, for which the walker deliberately skips
				// bare inline-source-at-sink synthesis (the two-step var form is
				// the supported firing shape).
				name:   "setattr_tainted_var",
				code:   "def upd(obj, v):\n    k = request.args['k']\n    setattr(obj, k, v)\n",
				sinkID: "py.setattr.massassign",
				line:   3,
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				flows := Analyze(tc.code, "/app/h.py", rules.LangPython)
				if !hasSinkFlow(flows, tc.sinkID, tc.line) {
					t.Errorf("expected %s flow at line %d for %s", tc.sinkID, tc.line, tc.name)
					for _, f := range flows {
						t.Logf("  flow: id=%s cwe=%s srcLine=%d sinkLine=%d", f.Sink.ID, f.Sink.CWEID, f.SourceLine, f.SinkLine)
					}
				}
			})
		}
	})

	t.Run("safe", func(t *testing.T) {
		cases := []struct {
			name   string
			code   string
			sinkID string
			line   int
		}{
			{
				// Flask/Django HTTP-verb dispatch: the name is request.method
				// normalised through .lower(), drawn from the fixed verb set.
				// FAIL-then-PASS anchor for the constrained-name gate (without it
				// the inline request.method source FP-fires).
				name:   "getattr_request_method_lower",
				code:   "def dispatch(self):\n    return getattr(self, request.method.lower())\n",
				sinkID: "py.getattr.reflection",
				line:   2,
			},
			{
				// request.method without the case-transform wrapper.
				name:   "getattr_request_method_bare",
				code:   "def dispatch(self):\n    return getattr(self, request.method)\n",
				sinkID: "py.getattr.reflection",
				line:   2,
			},
			{
				// Model-metadata iteration: field.name is a schema-bounded name.
				name:   "getattr_field_name",
				code:   "def ser(obj, field):\n    return getattr(obj, field.name)\n",
				sinkID: "py.getattr.reflection",
				line:   2,
			},
			{
				// Loop variable bound by iterating model metadata (_meta.fields).
				name:   "getattr_metadata_loop_var",
				code:   "def ser(obj):\n    for f in obj._meta.fields:\n        getattr(obj, f.name)\n",
				sinkID: "py.getattr.reflection",
				line:   3,
			},
			{
				// setattr with a model-metadata name — must not fire (CWE-915).
				name:   "setattr_field_name",
				code:   "def upd(self, field, v):\n    setattr(self, field.name, v)\n",
				sinkID: "py.setattr.massassign",
				line:   2,
			},
			{
				// String-literal name → fixed.
				name:   "getattr_string_literal",
				code:   "def h(obj):\n    return getattr(obj, 'secret_field')\n",
				sinkID: "py.getattr.reflection",
				line:   2,
			},
			{
				// Literal dispatch-table value: keys may be tainted, but the
				// returned value is one of the fixed dict values.
				name:   "getattr_literal_dispatch_table",
				code:   "def h(obj):\n    actions = {'a': 'foo', 'b': 'bar'}\n    name = request.args['a']\n    return getattr(obj, actions[name])\n",
				sinkID: "py.getattr.reflection",
				line:   4,
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				flows := Analyze(tc.code, "/app/h.py", rules.LangPython)
				if hasSinkFlow(flows, tc.sinkID, tc.line) {
					t.Errorf("FALSE POSITIVE: %s flow at line %d for %s", tc.sinkID, tc.line, tc.name)
					for _, f := range flows {
						t.Logf("  flow: id=%s cwe=%s srcLine=%d sinkLine=%d", f.Sink.ID, f.Sink.CWEID, f.SourceLine, f.SinkLine)
					}
				}
			})
		}
	})
}

// TestRejectConstrainedName_DefaultZeroIsNoOp documents the #1259 guardrail: a
// sink that does NOT set RejectConstrainedName is unaffected. A plain arg-payload
// command-exec sink with a request.method-derived argument still fires, proving
// the recogniser only runs for opted-in sinks (byte-identical otherwise).
func TestRejectConstrainedName_DefaultZeroIsNoOp(t *testing.T) {
	// os.system(request.method) — os.system does not set RejectConstrainedName,
	// so the constrained-name recogniser is never consulted and the flow fires.
	code := "import os\ndef h():\n    os.system(request.method)\n"
	flows := Analyze(code, "/app/h.py", rules.LangPython)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand && f.SinkLine == 3 {
			found = true
		}
	}
	if !found {
		t.Error("expected command-exec flow to fire unchanged for a non-opted-in sink")
	}
}
