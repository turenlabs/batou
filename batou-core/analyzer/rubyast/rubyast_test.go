package rubyast

import (
	"testing"
	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

func scanRuby(code string) []rules.Finding {
	tree := ast.Parse([]byte(code), rules.LangRuby)
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.rb",
		Content:  code,
		Language: rules.LangRuby,
		Tree:     tree,
	}
	a := &RubyASTAnalyzer{}
	return a.Scan(ctx)
}

func findByRule(findings []rules.Finding, ruleID string) *rules.Finding {
	for i := range findings {
		if findings[i].RuleID == ruleID {
			return &findings[i]
		}
	}
	return nil
}

func TestEvalVariable(t *testing.T) {
	code := `
def handler(input)
    eval(input)
end
`
	findings := scanRuby(code)
	f := findByRule(findings, "BATOU-RUBYAST-001")
	if f == nil {
		t.Error("expected eval finding")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestInstanceEval(t *testing.T) {
	code := `
def handler(input)
    instance_eval(input)
end
`
	findings := scanRuby(code)
	f := findByRule(findings, "BATOU-RUBYAST-001")
	if f == nil {
		t.Error("expected instance_eval finding")
	}
}

func TestEvalLiteralSafe(t *testing.T) {
	code := `eval("1 + 2")`
	findings := scanRuby(code)
	for _, f := range findings {
		if f.RuleID == "BATOU-RUBYAST-001" {
			t.Errorf("should not flag eval with literal: %s", f.Title)
		}
	}
}

// TestEvalOnReceiverIsNotKernelEval — `redis.eval(script, keys)` is the
// Redis client's Lua-script invocation, `template.eval(input)` is a
// template engine, etc. None of these are Ruby's Kernel#eval. Same
// receiver-gate shape as TestExecOnReceiverIsNotKernelExec.
//
// scan_harness sample: discourse's cached_counting.rb line 125 fires
// `LUA_HGET_DEL.eval(redis, [COUNTER_REDIS_HASH, key])` (Redis script
// eval) — surfaced as Critical CWE-95 before this gate.
func TestEvalOnReceiverIsNotKernelEval(t *testing.T) {
	cases := []struct {
		name string
		code string
	}{
		{"redis script eval", `
def increment(redis, key)
    LUA_HGET_DEL.eval(redis, [COUNTER_REDIS_HASH, key])
end
`},
		{"engine.eval with template", `
def render(template, ctx)
    engine.eval(template, ctx)
end
`},
		{"client.eval rpc", `
def call(req)
    client.eval(req)
end
`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, f := range scanRuby(tc.code) {
				if f.RuleID == "BATOU-RUBYAST-001" {
					t.Errorf("should NOT fire RUBYAST-001 on %s: %s line=%d",
						tc.name, f.MatchedText, f.LineNumber)
				}
			}
		})
	}
}

// TestKernelEvalBareCallStillFlags guards against over-suppression:
// bare eval(content) without a receiver is genuinely Kernel#eval and
// must keep firing.
func TestKernelEvalBareCallStillFlags(t *testing.T) {
	code := `
def load_config(content)
    eval(content)
end
`
	if findByRule(scanRuby(code), "BATOU-RUBYAST-001") == nil {
		t.Error("bare eval(content) is Kernel#eval — should still fire RUBYAST-001")
	}
}

// TestClassEvalBlockArgSafe covers the framework DSL pattern used by
// Sinatra/Rack/Devise/OmniAuth/Rails: class_eval(&block) where the block is
// developer-controlled at framework boot time.
func TestClassEvalBlockArgSafe(t *testing.T) {
	code := `
def helpers(*extensions, &block)
    class_eval(&block) if block_given?
end
`
	findings := scanRuby(code)
	if f := findByRule(findings, "BATOU-RUBYAST-001"); f != nil {
		t.Errorf("should not flag class_eval(&block): %s", f.MatchedText)
	}
}

// TestInstanceEvalBlockArgSafe — same DSL pattern with instance_eval.
func TestInstanceEvalBlockArgSafe(t *testing.T) {
	code := `
def configure(&block)
    instance_eval(&block)
end
`
	findings := scanRuby(code)
	if f := findByRule(findings, "BATOU-RUBYAST-001"); f != nil {
		t.Errorf("should not flag instance_eval(&block): %s", f.MatchedText)
	}
}

// TestClassEvalBlockLiteralSafe — class_eval { ... } is the same DSL pattern
// without an explicit &block argument.
func TestClassEvalBlockLiteralSafe(t *testing.T) {
	code := `
class_eval do
    def foo
        @bar
    end
end
`
	findings := scanRuby(code)
	if f := findByRule(findings, "BATOU-RUBYAST-001"); f != nil {
		t.Errorf("should not flag class_eval do...end: %s", f.MatchedText)
	}
}

// TestClassEvalHeredocFrameworkSafe covers the Devise/OmniAuth pattern of
// generating helper methods via a HEREDOC where every interpolation is a
// framework-internal local (mapping name, attribute, etc.).
func TestClassEvalHeredocFrameworkSafe(t *testing.T) {
	code := `
def define_helpers(name)
    class_eval <<-METHODS, __FILE__, __LINE__ + 1
      def #{name}?
        @#{name}
      end
    METHODS
end
`
	findings := scanRuby(code)
	if f := findByRule(findings, "BATOU-RUBYAST-001"); f != nil {
		t.Errorf("should not flag framework HEREDOC: %s", f.MatchedText)
	}
}

// TestClassEvalHeredocSqueezeSafe — squiggly HEREDOC variant (<<~).
func TestClassEvalHeredocSqueezeSafe(t *testing.T) {
	code := `
class_eval <<~RUBY
    def foo; @foo; end
RUBY
`
	findings := scanRuby(code)
	if f := findByRule(findings, "BATOU-RUBYAST-001"); f != nil {
		t.Errorf("should not flag squiggly HEREDOC: %s", f.MatchedText)
	}
}

// TestClassEvalUserInputArgFires — bare local that *might* hold params data
// is still flagged, since we cannot prove safety.
func TestClassEvalUserInputArgFires(t *testing.T) {
	code := `class_eval(params[:code])`
	findings := scanRuby(code)
	if f := findByRule(findings, "BATOU-RUBYAST-001"); f == nil {
		t.Error("expected class_eval(params[:code]) to fire")
	}
}

// TestClassEvalStringWithUserInterpolationFires — strings with #{params[...]}
// interpolations are real injection sinks.
func TestClassEvalStringWithUserInterpolationFires(t *testing.T) {
	code := `class_eval("def foo; #{params[:x]}; end")`
	findings := scanRuby(code)
	if f := findByRule(findings, "BATOU-RUBYAST-001"); f == nil {
		t.Error("expected class_eval with user-input interpolation to fire")
	}
}

// TestClassEvalHeredocUserInputFires — HEREDOC whose interpolation references
// `params` should still fire.
func TestClassEvalHeredocUserInputFires(t *testing.T) {
	code := `
class_eval <<-RUBY
    def foo; #{params[:x]}; end
RUBY
`
	findings := scanRuby(code)
	if f := findByRule(findings, "BATOU-RUBYAST-001"); f == nil {
		t.Error("expected HEREDOC with params interpolation to fire")
	}
}

func TestSystemVariable(t *testing.T) {
	code := `
def handler(cmd)
    system(cmd)
end
`
	findings := scanRuby(code)
	f := findByRule(findings, "BATOU-RUBYAST-002")
	if f == nil {
		t.Error("expected command injection finding for system()")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestExecVariable(t *testing.T) {
	code := `
def handler(cmd)
    exec(cmd)
end
`
	findings := scanRuby(code)
	f := findByRule(findings, "BATOU-RUBYAST-002")
	if f == nil {
		t.Error("expected command injection finding for exec()")
	}
}

func TestSystemLiteralSafe(t *testing.T) {
	code := `system("ls -la")`
	findings := scanRuby(code)
	for _, f := range findings {
		if f.RuleID == "BATOU-RUBYAST-002" {
			t.Errorf("should not flag system with literal: %s", f.Title)
		}
	}
}

// TestExecOnReceiverIsNotKernelExec regression-tests the receiver gate.
// DB.exec(sql, params), connection.exec(sql), redis.exec, etc. are SQL/RPC
// client wrappers that happen to share the name "exec" with Kernel#exec
// but are not OS command execution. Only bare exec(...) is Kernel#exec.
func TestExecOnReceiverIsNotKernelExec(t *testing.T) {
	cases := []struct {
		name string
		code string
	}{
		{"DB.exec with sql variable", `
def update_users(sql)
    DB.exec(sql, user_history_actions.slice(:flagged))
end
`},
		{"connection.exec with HEREDOC", `
def cleanup
    connection.exec <<~SQL
      DELETE FROM post_timings WHERE post_id NOT IN (SELECT id FROM posts)
    SQL
end
`},
		{"redis.exec pipeline", `
def push(item)
    redis.exec(item)
end
`},
		{"client.exec on rpc client", `
def call(req)
    client.exec(req)
end
`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, f := range scanRuby(tc.code) {
				if f.RuleID == "BATOU-RUBYAST-002" {
					t.Errorf("should NOT fire RUBYAST-002 on %s: %s line=%d",
						tc.name, f.MatchedText, f.LineNumber)
				}
			}
		})
	}
}

// TestKernelExecBareCallStillFlags guards against over-suppression: bare
// exec(cmd) without a receiver is genuinely Kernel#exec and must keep firing.
func TestKernelExecBareCallStillFlags(t *testing.T) {
	code := `
def run(cmd)
    exec(cmd)
end
`
	if findByRule(scanRuby(code), "BATOU-RUBYAST-002") == nil {
		t.Error("bare exec(cmd) is Kernel#exec — should still fire RUBYAST-002")
	}
}

// TestSystemMultiArgIsNotFlagged covers the dominant FP shape surfaced
// by scan_harness on Homebrew/discourse: multi-arg system/exec calls
// invoke the program directly via execve(2), so user-controlled values
// in any argv position cannot inject commands. Ruby only spawns a
// shell when system is called with a single string argument.
func TestSystemMultiArgIsNotFlagged(t *testing.T) {
	cases := map[string]string{
		"system multi-arg with variables": `
def install(brew, name)
    system(brew, "install", "--overwrite", name)
end
`,
		"exec multi-arg with splat": `
def reexec(cmd)
    exec("/usr/local/bin/brew", cmd, *ARGV)
end
`,
		"exec single splat": `
def run(args)
    exec(*args)
end
`,
		"system single splat": `
def run(command)
    system(*command)
end
`,
		"system multi-arg with kwargs": `
def install(brew_file)
    system(brew_file, "install", verbose: true)
end
`,
	}
	for name, code := range cases {
		t.Run(name, func(t *testing.T) {
			for _, f := range scanRuby(code) {
				if f.RuleID == "BATOU-RUBYAST-002" {
					t.Errorf("multi-arg / splat system|exec should not fire RUBYAST-002: %s",
						f.MatchedText)
				}
			}
		})
	}
}

// TestSystemSingleArgWithInterpolationStillFlags guards against
// over-suppression: the dangerous shell-form `system("ls #{user_input}")`
// still has a single argument; the rule must continue to fire.
func TestSystemSingleArgWithInterpolationStillFlags(t *testing.T) {
	code := `
def search(user_input)
    system("ls -la " + user_input)
end
`
	if findByRule(scanRuby(code), "BATOU-RUBYAST-002") == nil {
		t.Error("single-string system with concatenation should still fire RUBYAST-002")
	}
}

func TestSendVariable(t *testing.T) {
	code := `
def handler(input)
    send(input.to_sym, arg)
end
`
	findings := scanRuby(code)
	f := findByRule(findings, "BATOU-RUBYAST-003")
	if f == nil {
		t.Error("expected dynamic dispatch finding for send()")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

// TestSendMetaprogrammingDoesNotFire covers the dominant FP shape that
// scan_harness surfaced: Ruby metaprogramming with a developer-defined
// method name local variable (e.g. Sidekiq's `send synchronized_getter`,
// Kamal's `YAML.send(load_method, ...)`). The variable name doesn't
// match the user-input heuristic so the rule should not fire.
func TestSendMetaprogrammingDoesNotFire(t *testing.T) {
	code := `
def configure(load_method, rendered)
    YAML.send(load_method, rendered)
    send(synchronized_getter)
    singleton_class.send(name)
    self.class.public_send(name)
end
`
	findings := scanRuby(code)
	for _, f := range findings {
		if f.RuleID == "BATOU-RUBYAST-003" {
			t.Errorf("metaprogramming send with non-user-input variable name should not fire RUBYAST-003: %s line=%d",
				f.MatchedText, f.LineNumber)
		}
	}
}

// TestSendWithUserInputNameFires keeps the rule active for the obvious
// dangerous shape: a variable whose name signals it came from external
// input.
func TestSendWithUserInputNameFires(t *testing.T) {
	code := `
def handler(params)
    user_input = params[:method]
    target.send(user_input)
end
`
	findings := scanRuby(code)
	if findByRule(findings, "BATOU-RUBYAST-003") == nil {
		t.Error("expected RUBYAST-003 for .send(user_input) — variable name hints at external input")
	}
}

// TestSendAllowlistGuardSuppressed reproduces the real-world Discourse FP
// shape: a send/public_send whose method-name argument is checked against an
// allowlist earlier in the same method. The value is provably one of a known
// set before reaching the sink, so RUBYAST-003 must NOT fire. This is the
// regression test for the allowlist-guard recogniser
// (rubyast_allowlist_guard.go).
func TestSendAllowlistGuardSuppressed(t *testing.T) {
	cases := map[string]string{
		// Discourse topics_bulk_action.rb shape: exclude?-guard then raise.
		"exclude? membership guard then raise": `
def perform!
    if TopicsBulkAction.operations.exclude?(@operation[:type])
      raise Discourse::InvalidParameters.new(:operation)
    end
    send(@operation[:type])
end
`,
		// include? allowlist guard with early return.
		"include? allowlist guard then return": `
def dispatch(params)
    name = params[:action]
    return unless ALLOWED_METHODS.include?(name)
    public_send(name)
end
`,
		// has_*? predicate guard.
		"has_setting? predicate guard": `
def apply(params)
    setting = params[:setting]
    return unless SiteSetting.has_setting?(setting)
    public_send(setting)
end
`,
		// valid_*? predicate guard.
		"valid_type? predicate guard": `
def run(params)
    kind = params[:kind]
    raise ArgumentError unless valid_type?(kind)
    send(kind)
end
`,
	}
	for name, code := range cases {
		findings := scanRuby(code)
		for _, f := range findings {
			if f.RuleID == "BATOU-RUBYAST-003" {
				t.Errorf("%s: allowlist-guarded dispatch should NOT fire RUBYAST-003 (line %d)",
					name, f.LineNumber)
			}
		}
	}
}

// TestSendUnguardedStillFires proves the allowlist-guard recogniser TIGHTENS
// rather than DISABLES: a dispatch with no guard, or one whose guard validates
// a DIFFERENT value, must STILL fire RUBYAST-003.
func TestSendUnguardedStillFires(t *testing.T) {
	cases := map[string]string{
		// No guard at all — the canonical TP.
		"no guard": `
def handler(params)
    user_input = params[:method]
    target.send(user_input)
end
`,
		// Guard validates an UNRELATED value (other), not the dispatched name.
		"allowlist guard on unrelated value": `
def handler(params)
    user_input = params[:method]
    other = params[:scope]
    return unless ALLOWED.include?(other)
    target.send(user_input)
end
`,
	}
	for name, code := range cases {
		if findByRule(scanRuby(code), "BATOU-RUBYAST-003") == nil {
			t.Errorf("%s: should STILL fire RUBYAST-003 (recogniser must tighten, not disable)", name)
		}
	}
}

func TestIOPopen(t *testing.T) {
	code := `
def handler(cmd)
    IO.popen(cmd)
end
`
	findings := scanRuby(code)
	f := findByRule(findings, "BATOU-RUBYAST-004")
	if f == nil {
		t.Error("expected IO.popen finding")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestERBNew(t *testing.T) {
	code := `
def handler(template)
    ERB.new(template).result
end
`
	findings := scanRuby(code)
	f := findByRule(findings, "BATOU-RUBYAST-005")
	if f == nil {
		t.Error("expected ERB.new finding")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestERBNewLiteralSafe(t *testing.T) {
	code := `ERB.new("<p>Hello</p>").result`
	findings := scanRuby(code)
	for _, f := range findings {
		if f.RuleID == "BATOU-RUBYAST-005" {
			t.Errorf("should not flag ERB.new with literal: %s", f.Title)
		}
	}
}

func TestNilTree(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.rb",
		Content:  "eval(x)",
		Language: rules.LangRuby,
		Tree:     nil,
	}
	a := &RubyASTAnalyzer{}
	findings := a.Scan(ctx)
	if len(findings) != 0 {
		t.Error("expected no findings with nil tree")
	}
}

func TestWrongLanguage(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.py",
		Content:  "eval(x)",
		Language: rules.LangPython,
	}
	a := &RubyASTAnalyzer{}
	findings := a.Scan(ctx)
	if len(findings) != 0 {
		t.Error("expected no findings for wrong language")
	}
}

func TestLineNumbers(t *testing.T) {
	code := `
# comment
def handler(input)
    eval(input)
end
`
	findings := scanRuby(code)
	f := findByRule(findings, "BATOU-RUBYAST-001")
	if f == nil {
		t.Fatal("expected finding")
	}
	if f.LineNumber != 4 {
		t.Errorf("expected line 4, got %d", f.LineNumber)
	}
}
