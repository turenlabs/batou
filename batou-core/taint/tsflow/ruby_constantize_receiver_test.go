package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// hasConstantizeFlow reports whether any flow reaches the ruby.constantize
// sink (CWE-470 dynamic class instantiation) at the given line.
func hasConstantizeFlow(flows []taint.TaintFlow, line int) bool {
	for _, f := range flows {
		if f.Sink.ID == "ruby.constantize" && f.SinkLine == line {
			return true
		}
	}
	return false
}

// TestRuby_Constantize_DirectSourceReceiver covers the recall gap: a tainted
// value reaching String#constantize as the RECEIVER in a single expression
// (`params[:type].constantize`) — the railsgoat BenefitFormsController#download
// and Api::V1::MobileController shape. Before the receiver inline-source
// synthesis in processCall, this only produced a regex-tier hint; the dataflow
// engine missed it because callReceiverTainted only resolves a tracked tainted
// VARIABLE, not a raw source expression sitting in the receiver position.
func TestRuby_Constantize_DirectSourceReceiver(t *testing.T) {
	code := `
class BenefitFormsController < ApplicationController
  def download
    file = params[:type].constantize.new(path)
  end
end
`
	flows := Analyze(code, "/app/controllers/benefit_forms_controller.rb", rules.LangRuby)
	if !hasConstantizeFlow(flows, 4) {
		t.Error("expected CWE-470 constantize flow for params[:type].constantize (direct-source receiver)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s, line=%d)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID, f.SinkLine)
		}
	}
}

// TestRuby_Constantize_ChainedClassify covers the chained-inflection form
// `params[:class].classify.constantize` (railsgoat Api::V1::MobileController).
// ActiveSupport String#classify only transforms the class name and preserves
// attacker control — it is NOT a sanitizer — so the raw source sits one call
// deeper than the immediate receiver and must still be resolved.
func TestRuby_Constantize_ChainedClassify(t *testing.T) {
	code := `
class MobileController < ApplicationController
  def show
    model = params[:class].classify.constantize
  end
end
`
	flows := Analyze(code, "/app/controllers/mobile_controller.rb", rules.LangRuby)
	if !hasConstantizeFlow(flows, 4) {
		t.Error("expected CWE-470 constantize flow for params[:class].classify.constantize")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s, line=%d)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID, f.SinkLine)
		}
	}
}

// TestRuby_Constantize_TwoStepReceiver is the pre-existing two-step form that
// already worked (the receiver is a tracked tainted variable). Guards against
// the change accidentally regressing it.
func TestRuby_Constantize_TwoStepReceiver(t *testing.T) {
	code := `
class C < ApplicationController
  def show
    t = params[:type]
    klass = t.constantize
  end
end
`
	flows := Analyze(code, "/app/c.rb", rules.LangRuby)
	if !hasConstantizeFlow(flows, 5) {
		t.Error("expected CWE-470 constantize flow for two-step t = params[:type]; t.constantize")
	}
}

// TestRuby_Constantize_SafeForms is THE false-positive gate: a literal
// receiver, a constant receiver, and an interpolation-free constant string
// must NOT produce a constantize dataflow finding. constantize on
// attacker-uncontrolled receivers is benign and pervasive in Rails apps.
func TestRuby_Constantize_SafeForms(t *testing.T) {
	cases := []struct {
		name string
		code string
		line int
	}{
		{
			name: "literal_receiver",
			code: "\nclass C\n  def a\n    k = \"User\".constantize\n  end\nend\n",
			line: 4,
		},
		{
			name: "constant_receiver",
			code: "\nclass C\n  MODEL = \"User\".freeze\n  def a\n    k = MODEL.constantize\n  end\nend\n",
			line: 5,
		},
		{
			name: "constant_interpolated_receiver",
			code: "\nclass C\n  PREFIX = \"Admin\".freeze\n  def a\n    k = \"#{PREFIX}User\".constantize\n  end\nend\n",
			line: 5,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flows := Analyze(tc.code, "/app/safe.rb", rules.LangRuby)
			if hasConstantizeFlow(flows, tc.line) {
				t.Errorf("FALSE POSITIVE: constantize dataflow flagged on safe %s", tc.name)
				for _, f := range flows {
					t.Logf("  flow: %s -> %s (id=%s, line=%d)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.SinkLine)
				}
			}
		})
	}
}

// TestRuby_EvalSend_AlreadyWorks documents that the eval / dynamic-dispatch
// halves of the lever already fire via the dangerous-ARGUMENT path (no change
// was needed for them), and guards against a regression. eval(tainted),
// eval("...#{tainted}..."), obj.send(tainted_name) and public_send(tainted)
// all reach SnkEval; the static-symbol/static-string/literal forms do not.
func TestRuby_EvalSend_AlreadyWorks(t *testing.T) {
	vuln := []struct {
		name string
		code string
	}{
		{"eval_tainted_var", "\nclass C\n  def a\n    code = params[:code]\n    eval(code)\n  end\nend\n"},
		{"eval_interpolated", "\nclass C\n  def a\n    eval(\"x = #{params[:x]}\")\n  end\nend\n"},
		{"send_tainted_var", "\nclass C\n  def a\n    m = params[:method]\n    obj.send(m)\n  end\nend\n"},
		{"public_send_tainted_arg", "\nclass C\n  def a\n    record.public_send(params[:action])\n  end\nend\n"},
	}
	for _, tc := range vuln {
		t.Run(tc.name, func(t *testing.T) {
			flows := Analyze(tc.code, "/app/c.rb", rules.LangRuby)
			if !hasTaintFlow(flows, taint.SnkEval) {
				t.Errorf("expected SnkEval flow for %s", tc.name)
			}
		})
	}

	safe := []struct {
		name string
		code string
	}{
		{"send_static_symbol", "\nclass C\n  def a\n    obj.send(:save)\n  end\nend\n"},
		{"send_static_string", "\nclass C\n  def a\n    obj.send(\"update_name\")\n  end\nend\n"},
		{"eval_literal", "\nclass C\n  def a\n    eval(\"1 + 1\")\n  end\nend\n"},
	}
	for _, tc := range safe {
		t.Run("safe_"+tc.name, func(t *testing.T) {
			flows := Analyze(tc.code, "/app/c.rb", rules.LangRuby)
			if hasTaintFlow(flows, taint.SnkEval) {
				t.Errorf("FALSE POSITIVE: SnkEval flow on safe %s", tc.name)
			}
		})
	}
}

// hasSendFlow reports whether any flow reaches the ruby.send / ruby.public_send
// reflective-dispatch sink (CWE-94).
func hasSendFlow(flows []taint.TaintFlow) bool {
	for _, f := range flows {
		if f.Sink.ID == "ruby.send" || f.Sink.ID == "ruby.public_send" {
			return true
		}
	}
	return false
}

// TestRuby_SendPublicSend_PayloadArgOnly is the load-bearing test for scoping
// send/public_send to the method-NAME argument (PayloadPosition:PayloadArgOnly).
// The genuine reflective-dispatch RCE is a TAINTED method name
// (`obj.public_send(params[:m])`) — that must still fire. The idiomatic Rails
// attribute-writer / save form runs on a DB-loaded (internally-tainted) RECEIVER
// with a literal or whitelisted method name; PayloadArgOnly turns off the
// receiver-taint fallback so those benign shapes no longer false-fire CWE-94
// (the discourse themes/user_fields/auth-result/sentiment block FPs).
func TestRuby_SendPublicSend_PayloadArgOnly(t *testing.T) {
	// Tainted RECEIVER, literal/whitelisted NAME → receiver fallback suppressed.
	safe := []struct {
		name string
		code string
	}{
		{
			name: "public_send_literal_tainted_receiver",
			code: "\nclass C\n  def a\n    record = User.find(params[:id])\n    record.public_send(\"literal\")\n  end\nend\n",
		},
		{
			name: "public_send_attr_writer_tainted_receiver",
			code: "\nclass C\n  def a\n    record = User.find(params[:id])\n    record.public_send(\"#{whitelist}=\", value)\n  end\nend\n",
		},
		{
			name: "send_symbol_tainted_receiver",
			code: "\nclass C\n  def a\n    record = User.find(params[:id])\n    record.send(:save)\n  end\nend\n",
		},
	}
	for _, tc := range safe {
		t.Run("safe_"+tc.name, func(t *testing.T) {
			flows := Analyze(tc.code, "/app/c.rb", rules.LangRuby)
			if hasSendFlow(flows) {
				t.Errorf("FALSE POSITIVE: send/public_send flow on safe %s (tainted receiver, literal name)", tc.name)
				for _, f := range flows {
					t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
				}
			}
		})
	}

	// Tainted NAME argument → genuine reflective-dispatch RCE, must STILL fire.
	vuln := []struct {
		name string
		code string
	}{
		{
			name: "public_send_tainted_name_inline",
			code: "\nclass C\n  def a\n    obj.public_send(params[:m])\n  end\nend\n",
		},
		{
			name: "send_tainted_name_two_step",
			code: "\nclass C\n  def a\n    m = params[:m]\n    obj.send(m)\n  end\nend\n",
		},
	}
	for _, tc := range vuln {
		t.Run("vuln_"+tc.name, func(t *testing.T) {
			flows := Analyze(tc.code, "/app/c.rb", rules.LangRuby)
			if !hasSendFlow(flows) {
				t.Errorf("expected send/public_send CWE-94 flow for %s (tainted method name)", tc.name)
			}
		})
	}
}
