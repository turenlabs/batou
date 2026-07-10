package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Weak (wildcard / @global) sink candidates are re-validated against their own
// catalog Pattern before firing (weakSinkPatternOK). The tsflow matcher keys
// sinks on the unqualified method/command NAME, so an empty-ObjectType sink
// whose catalog MethodName is actually qualified or argument-constrained matched
// ANY same-named call and produced hard-block false positives. Each case below
// pairs a benign collision (must NOT flag) with the genuine form (must flag).

// Perl: `IPC::Run::run` (CWE-78) keyed under bare `run` collided with
// Mojolicious `commands->run(@ARGV)` (a subcommand dispatcher) at conf 1.0.
// The genuine `IPC::Run::run($cmd)` TP is covered by
// TestPerl_IPCRun_CommandInjection, which still passes under the Pattern gate.
func TestPerl_IPCRun_BareNameCollision(t *testing.T) {
	benign := `
package Mojolicious;
sub start {
    my $self = shift;
    return $self->commands->run(@ARGV);
}
`
	if hasTaintFlow(Analyze(benign, "/app/Mojolicious.pm", rules.LangPerl), taint.SnkCommand) {
		t.Error("FP: commands->run(@ARGV) must not match the IPC::Run::run command-exec sink")
	}
}

// Shell: the `git` SSRF sink (CWE-918) is Pattern-anchored to the network
// subcommands clone/fetch/pull/ls-remote, but matched the bare command word
// `git` for every subcommand (547 FPs on the git repo: rev-parse, commit, …).
func TestShell_GitSSRF_SubcommandGate(t *testing.T) {
	benign := "read ref\ngit rev-parse \"$ref\"\n"
	if hasTaintFlow(Analyze(benign, "/app/x.sh", rules.LangShell), taint.SnkURLFetch) {
		t.Error("FP: `git rev-parse $ref` is not a network fetch and must not flag SSRF")
	}
	real := "read url\ngit clone \"$url\" /tmp/x\n"
	if !hasTaintFlow(Analyze(real, "/app/y.sh", rules.LangShell), taint.SnkURLFetch) {
		t.Error("FN: `git clone $url` must still flag SSRF")
	}
}

// JS: setInterval/setTimeout are eval sinks ONLY with a string first-arg; the
// @global Pattern requires the leading quote. A function-literal first-arg
// (the dominant idiom) must not flag CWE-94.
func TestJS_SetInterval_FunctionLiteralNotEval(t *testing.T) {
	benign := `
function poll(req) {
    const loc = req.query.path;
    setInterval(() => { fetch(loc); }, 1000);
}
`
	if hasTaintFlow(Analyze(benign, "/app/poll.js", rules.LangJavaScript), taint.SnkEval) {
		t.Error("FP: setInterval(fn, ms) must not flag code-eval — only a string first-arg evals")
	}
	real := `
function run(req) {
    const code = req.query.code;
    setInterval("doWork(" + code + ")", 1000);
}
`
	if !hasTaintFlow(Analyze(real, "/app/run.js", rules.LangJavaScript), taint.SnkEval) {
		t.Error("FN: setInterval with a tainted string (implicit eval) must still flag code-eval")
	}
}
