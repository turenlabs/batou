package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-rules/rules"

	"github.com/turenlabs/batou-core/taint"
)

// hasReflectiveSink reports whether any flow reaches the given sink ID with the
// expected CWE. The CWE assertion matters: the OWASP-style harness matches by
// CWE number, so a fire with the wrong CWE would not count as the intended
// detection.
func hasReflectiveSink(flows []taint.TaintFlow, sinkID, cwe string) bool {
	for _, f := range flows {
		if f.Sink.ID == sinkID && f.Sink.CWEID == cwe {
			return true
		}
	}
	return false
}

func anyReflectiveSink(flows []taint.TaintFlow, sinkID string) bool {
	for _, f := range flows {
		if f.Sink.ID == sinkID {
			return true
		}
	}
	return false
}

// TestRuby_ReflectiveNameSinks_FireOnTaintedName is the load-bearing test for
// the SLICE-3 revive of the HELD CWE-470/915 reflective-sink category. The
// sinks (instance_variable_set/get, define_method) are ObjectType:"" wildcard
// with a tight, call-anchored, non-wildcard Pattern (re-validated by
// weakSinkPatternOK) + DangerousArgs:[0]=name + PayloadPosition:PayloadArgOnly.
// The danger fires ONLY on a tainted NAME argument — never on a literal-symbol
// name (the idiomatic Rails form) and never on an incidentally-tainted
// receiver.
func TestRuby_ReflectiveNameSinks_FireOnTaintedName(t *testing.T) {
	vuln := []struct {
		name   string
		code   string
		sinkID string
		cwe    string
	}{
		{
			name:   "instance_variable_set_tainted_name",
			code:   "\nclass C\n  def a\n    obj.instance_variable_set(params[:f], v)\n  end\nend\n",
			sinkID: "ruby.instance_variable_set",
			cwe:    "CWE-915",
		},
		{
			name:   "instance_variable_set_tainted_name_two_step",
			code:   "\nclass C\n  def a\n    name = params[:f]\n    obj.instance_variable_set(name, v)\n  end\nend\n",
			sinkID: "ruby.instance_variable_set",
			cwe:    "CWE-915",
		},
		{
			name:   "define_method_tainted_name",
			code:   "\nclass C\n  def a\n    define_method(params[:m]) do\n      1\n    end\n  end\nend\n",
			sinkID: "ruby.define_method",
			cwe:    "CWE-470",
		},
		{
			name:   "instance_variable_get_tainted_name",
			code:   "\nclass C\n  def a\n    obj.instance_variable_get(params[:f])\n  end\nend\n",
			sinkID: "ruby.instance_variable_get",
			cwe:    "CWE-200",
		},
	}
	for _, tc := range vuln {
		t.Run(tc.name, func(t *testing.T) {
			flows := Analyze(tc.code, "/app/c.rb", rules.LangRuby)
			if !hasReflectiveSink(flows, tc.sinkID, tc.cwe) {
				t.Errorf("expected %s (%s) flow for %s; got %d flows", tc.sinkID, tc.cwe, tc.name, len(flows))
			}
		})
	}
}

// TestRuby_ReflectiveNameSinks_HeldFPDoNotFire pins the precise false-positive
// shapes the category was HELD for: a LITERAL symbol name (idiomatic Rails)
// must never fire, and a tainted RECEIVER with a literal name must never fire
// (PayloadArgOnly suppresses the receiver fallback). If any of these regress,
// the category goes back to flooding real Rails.
func TestRuby_ReflectiveNameSinks_HeldFPDoNotFire(t *testing.T) {
	safe := []struct {
		name   string
		code   string
		sinkID string
	}{
		{
			// The idiomatic Rails form: literal symbol name, value possibly tainted.
			name:   "ivar_set_literal_symbol_name",
			code:   "\nclass C\n  def a\n    obj.instance_variable_set(:@count, val)\n  end\nend\n",
			sinkID: "ruby.instance_variable_set",
		},
		{
			// PayloadArgOnly: receiver tainted, literal name → must NOT fire.
			name:   "ivar_set_tainted_receiver_literal_name",
			code:   "\nclass C\n  def a\n    obj = params[:target]\n    obj.instance_variable_set(:@x, 1)\n  end\nend\n",
			sinkID: "ruby.instance_variable_set",
		},
		{
			// String literal name (a different literal shape) → must NOT fire.
			name:   "ivar_set_literal_string_name",
			code:   "\nclass C\n  def a\n    obj.instance_variable_set(\"@total\", total)\n  end\nend\n",
			sinkID: "ruby.instance_variable_set",
		},
		{
			name:   "define_method_literal_symbol_name",
			code:   "\nclass C\n  def a\n    define_method(:foo) do\n      1\n    end\n  end\nend\n",
			sinkID: "ruby.define_method",
		},
		{
			name:   "ivar_get_literal_symbol_name",
			code:   "\nclass C\n  def a\n    x = obj.instance_variable_get(:@count)\n  end\nend\n",
			sinkID: "ruby.instance_variable_get",
		},
		{
			// PayloadArgOnly on the read form: tainted receiver, literal name.
			name:   "ivar_get_tainted_receiver_literal_name",
			code:   "\nclass C\n  def a\n    obj = params[:target]\n    x = obj.instance_variable_get(:@count)\n  end\nend\n",
			sinkID: "ruby.instance_variable_get",
		},
	}
	for _, tc := range safe {
		t.Run(tc.name, func(t *testing.T) {
			flows := Analyze(tc.code, "/app/c.rb", rules.LangRuby)
			if anyReflectiveSink(flows, tc.sinkID) {
				t.Errorf("FALSE POSITIVE: %s flagged on safe %s", tc.sinkID, tc.name)
			}
		})
	}
}
