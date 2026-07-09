package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Perl — Redis server-side Lua code injection (CWE-94)
//
// The CPAN Redis.pm / Redis::Fast clients expose EVAL, EVALSHA and
// SCRIPT LOAD. A tainted script body is arbitrary Lua executed inside
// the Redis server's scripting engine — CVE-2022-0543 showed the Debian
// package's Lua sandbox could even be escaped to full RCE on the host.
//
// Mirrors ruby.redis.eval, php.redis.eval, py.redis.eval,
// csharp.redis.scriptevaluate, js.redis.eval.
//
// Kept in a dedicated file to avoid the tsflow_test.go merge bottleneck.
// =========================================================================

// Redis EVAL — user-controlled Lua script body is CWE-94.
func TestPerl_Redis_Eval_TaintedScript(t *testing.T) {
	code := `
use CGI;
use Redis;
sub handler {
    my $cgi    = CGI->new;
    my $script = $cgi->param("script");
    my $redis  = Redis->new;
    return $redis->eval($script, 0);
}
`
	flows := Analyze(code, "/app/redis.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for CGI param -> $redis->eval")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Redis EVALSHA — user-controlled SHA-1 digest is still CWE-94:
// if the attacker controls which preloaded script runs, they can
// pick one with side effects. Same pattern as csharp/py/ruby.
func TestPerl_Redis_EvalSha_TaintedSha(t *testing.T) {
	code := `
use CGI;
use Redis;
sub handler {
    my $cgi   = CGI->new;
    my $sha   = $cgi->param("sha");
    my $redis = Redis->new;
    return $redis->evalsha($sha, 0);
}
`
	flows := Analyze(code, "/app/redis.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for CGI param -> $redis->evalsha")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Redis SCRIPT LOAD — loading a tainted script registers it for any later
// EVALSHA to execute. Same severity as EVAL because the script body is
// fully attacker-controlled.
func TestPerl_Redis_ScriptLoad_TaintedScript(t *testing.T) {
	code := `
use CGI;
use Redis;
sub handler {
    my $cgi    = CGI->new;
    my $script = $cgi->param("lua");
    my $redis  = Redis->new;
    return $redis->script_load($script);
}
`
	flows := Analyze(code, "/app/redis.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for CGI param -> $redis->script_load")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Safe baseline — EVALSHA against a hard-coded digest with tainted KEYS/ARGV
// is safe: the script body is literal, and Redis parameter-binding handles
// keys/args without string concatenation into Lua source.
func TestPerl_Redis_EvalSha_LiteralSha_Safe(t *testing.T) {
	code := `
use CGI;
use Redis;
sub handler {
    my $cgi   = CGI->new;
    my $key   = $cgi->param("key");
    my $redis = Redis->new;
    return $redis->evalsha("e0e1f9fabfc9d4800c877a703b823ac0578ff831", 1, $key);
}
`
	flows := Analyze(code, "/app/redis.pl", rules.LangPerl)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkEval {
			t.Errorf("unexpected SnkEval flow for literal SHA evalsha: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
