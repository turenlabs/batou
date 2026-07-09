package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Ruby — Eval sanitized by safe_constantize (CWE-470)
// =========================================================================

func TestRuby_Eval_Sanitized_SafeConstantize(t *testing.T) {
	code := `
def handler(params)
    class_name = params[:type]
    safe = class_name.safe_constantize
    eval(safe.to_s)
end
`
	flows := Analyze(code, "/app/handler.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkEval) {
		t.Error("safe_constantize should neutralize eval taint flow")
	}
}

func TestRuby_Eval_Unsanitized_Send(t *testing.T) {
	code := `
def handler(params)
    action = params[:action]
    self.send(action)
end
`
	flows := Analyze(code, "/app/handler.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for send() without sanitizer")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// =========================================================================
// Ruby — Eval sanitized by const_defined? guard (CWE-470)
// =========================================================================

func TestRuby_Eval_Sanitized_ConstDefined(t *testing.T) {
	code := `
def handler(params)
    name = params[:class_name]
    safe = Object.const_defined?(name)
    eval(safe.to_s)
end
`
	flows := Analyze(code, "/app/handler.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkEval) {
		t.Error("const_defined? should neutralize eval taint flow")
	}
}

// =========================================================================
// Ruby — Eval sanitized by method_defined? guard (CWE-94)
// =========================================================================

func TestRuby_Eval_Sanitized_MethodDefined(t *testing.T) {
	code := `
def handler(params)
    action = params[:action]
    safe = self.class.method_defined?(action)
    eval(safe.to_s)
end
`
	flows := Analyze(code, "/app/handler.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkEval) {
		t.Error("method_defined? should neutralize eval taint flow")
	}
}

func TestRuby_Eval_Sanitized_PrivateMethodDefined(t *testing.T) {
	code := `
def handler(params)
    method_name = params[:method]
    safe = self.class.private_method_defined?(method_name)
    eval(safe.to_s)
end
`
	flows := Analyze(code, "/app/handler.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkEval) {
		t.Error("private_method_defined? should neutralize eval taint flow")
	}
}

// =========================================================================
// Ruby — Command injection sanitized by Integer() strict conversion (CWE-78)
// =========================================================================

func TestRuby_Command_Sanitized_IntegerStrict(t *testing.T) {
	code := `
def handler(params)
    port = params[:port]
    safe_port = Integer(port)
    system("netstat -an | grep #{safe_port}")
end
`
	flows := Analyze(code, "/app/handler.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("Integer() strict conversion should neutralize command injection taint flow")
	}
}

func TestRuby_Eval_Sanitized_IntegerStrict(t *testing.T) {
	code := `
def handler(params)
    val = params[:value]
    safe_val = Integer(val)
    eval("result = #{safe_val}")
end
`
	flows := Analyze(code, "/app/handler.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkEval) {
		t.Error("Integer() strict conversion should neutralize eval taint flow")
	}
}

// =========================================================================
// Ruby — Command injection sanitized by Float() strict conversion (CWE-78)
// =========================================================================

func TestRuby_Command_Sanitized_FloatStrict(t *testing.T) {
	code := `
def handler(params)
    threshold = params[:threshold]
    safe = Float(threshold)
    system("check_metric --threshold #{safe}")
end
`
	flows := Analyze(code, "/app/handler.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("Float() strict conversion should neutralize command injection taint flow")
	}
}

func TestRuby_Eval_Sanitized_FloatStrict(t *testing.T) {
	code := `
def handler(params)
    val = params[:value]
    safe_val = Float(val)
    eval("x = #{safe_val}")
end
`
	flows := Analyze(code, "/app/handler.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkEval) {
		t.Error("Float() strict conversion should neutralize eval taint flow")
	}
}

// =========================================================================
// Negative tests — unsanitized flows must be detected
// =========================================================================

func TestRuby_Command_Unsanitized_NoIntegerConversion(t *testing.T) {
	code := `
def handler(params)
    port = params[:port]
    system("netstat -an | grep #{port}")
end
`
	flows := Analyze(code, "/app/handler.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow without Integer() conversion")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_Eval_Unsanitized_NoGuard(t *testing.T) {
	code := `
def handler(params)
    code = params[:code]
    eval(code)
end
`
	flows := Analyze(code, "/app/handler.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow without sanitizer")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
