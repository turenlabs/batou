package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// hasDeserFlow reports whether any flow reaches a CWE-502 deserialization sink
// at the given line.
func hasDeserFlow(flows []taint.TaintFlow, line int) bool {
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize && f.Sink.CWEID == "CWE-502" && f.SinkLine == line {
			return true
		}
	}
	return false
}

func anyDeserFlow(flows []taint.TaintFlow) bool {
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize && f.Sink.CWEID == "CWE-502" {
			return true
		}
	}
	return false
}

// TestRuby_Deser_WrappedInlineSource covers the recall gap: a tainted value
// nested inside a NON-source wrapper call (`Base64.decode64(params[:user])`)
// passed directly as the argument of an unsafe deserializer is the canonical
// railsgoat RCE (password_resets_controller.rb:6
// `Marshal.load(Base64.decode64(params[:user]))`). Before the argument
// recursion in findSourceInExpr, the wrapper call hid the inline `params[:user]`
// source from the sink — matchSourceCall returned nil for `Base64.decode64`
// and the receiver-chain recursion only walked `Base64`, never the argument —
// so the `ruby.marshal.load` dataflow sink was dead (regex-hint-only, conf 0.5)
// and the default dataflow-only scan dropped it entirely.
func TestRuby_Deser_WrappedInlineSource_Marshal(t *testing.T) {
	code := `
class PasswordResetsController < ApplicationController
  def reset
    user = Marshal.load(Base64.decode64(params[:user])) unless params[:user].nil?
  end
end
`
	flows := Analyze(code, "/app/controllers/password_resets_controller.rb", rules.LangRuby)
	if !hasDeserFlow(flows, 4) {
		t.Error("expected CWE-502 flow for Marshal.load(Base64.decode64(params[:user]))")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s, line=%d)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID, f.SinkLine)
		}
	}
}

// YAML.load of a wrapped inline source is the same shape on the YAML.load sink
// (CVE-2013-0156 / pre-Psych-4 RCE vector).
func TestRuby_Deser_WrappedInlineSource_YAMLLoad(t *testing.T) {
	code := `
class ImportsController < ApplicationController
  def create
    obj = YAML.load(Base64.decode64(params[:blob]))
  end
end
`
	flows := Analyze(code, "/app/controllers/imports_controller.rb", rules.LangRuby)
	if !hasDeserFlow(flows, 4) {
		t.Error("expected CWE-502 flow for YAML.load(Base64.decode64(params[:blob]))")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s, line=%d)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID, f.SinkLine)
		}
	}
}

// YAML.unsafe_load of a wrapped inline source (Ruby 3.1+ explicit-unsafe form).
func TestRuby_Deser_WrappedInlineSource_YAMLUnsafeLoad(t *testing.T) {
	code := `
class ImportsController < ApplicationController
  def create
    obj = YAML.unsafe_load(Base64.decode64(params[:blob]))
  end
end
`
	flows := Analyze(code, "/app/controllers/imports_controller.rb", rules.LangRuby)
	if !hasDeserFlow(flows, 4) {
		t.Error("expected CWE-502 flow for YAML.unsafe_load(Base64.decode64(params[:blob]))")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s, line=%d)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID, f.SinkLine)
		}
	}
}

// NEGATIVE: YAML.safe_load is the safe deserializer (not an unsafe sink) — it
// must NOT fire even though its argument is a wrapped inline source.
func TestRuby_Deser_WrappedInlineSource_SafeLoad_NoFlow(t *testing.T) {
	code := `
class ImportsController < ApplicationController
  def create
    obj = YAML.safe_load(Base64.decode64(params[:blob]))
  end
end
`
	flows := Analyze(code, "/app/controllers/imports_controller.rb", rules.LangRuby)
	if anyDeserFlow(flows) {
		t.Error("YAML.safe_load(Base64.decode64(params[:blob])) must NOT produce a CWE-502 flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s, line=%d)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID, f.SinkLine)
		}
	}
}

// NEGATIVE: JSON.parse is the safe alternative to JSON.load — it must NOT fire.
func TestRuby_Deser_WrappedInlineSource_JSONParse_NoFlow(t *testing.T) {
	code := `
class ImportsController < ApplicationController
  def create
    obj = JSON.parse(params[:blob])
  end
end
`
	flows := Analyze(code, "/app/controllers/imports_controller.rb", rules.LangRuby)
	if anyDeserFlow(flows) {
		t.Error("JSON.parse(params[:blob]) must NOT produce a CWE-502 flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s, line=%d)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID, f.SinkLine)
		}
	}
}

// NEGATIVE: Marshal.load / YAML.load of a literal or an app-controlled
// constant carries no taint source, so the argument recursion finds nothing
// and nothing fires. (Note: File.read is intentionally a registered source in
// the catalog and is deliberately excluded from this no-taint set.)
func TestRuby_Deser_WrappedInlineSource_NoTaint_NoFlow(t *testing.T) {
	code := `
class BootController < ApplicationController
  def warm
    b = Marshal.load("\x04\b0")
    c = Marshal.load(SOME_CONST)
    d = YAML.load("static: true")
  end
end
`
	flows := Analyze(code, "/app/controllers/boot_controller.rb", rules.LangRuby)
	if anyDeserFlow(flows) {
		t.Error("Marshal.load of a literal / constant-path File.read must NOT produce a CWE-502 flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s, line=%d)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID, f.SinkLine)
		}
	}
}
