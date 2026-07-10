package tsflow

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	"testing"
)

// --- Command Injection via Command::args (CWE-78) ---

func TestRust_CommandArgs_EnvVar(t *testing.T) {
	code := `
use std::env;
use std::process::Command;

fn run_tool() {
    let input = env::var("USER_ARGS").unwrap();
    let mut cmd = Command::new("mytool");
    cmd.args(input);
}
`
	flows := Analyze(code, "/app/runner.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for env::var -> Command::args")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Command Injection via libc::system (CWE-78) ---

func TestRust_LibcSystem_EnvVar(t *testing.T) {
	code := `
use std::env;
use std::ffi::CString;

fn run_shell() {
    let cmd = env::var("USER_CMD").unwrap();
    let c_cmd = CString::new(cmd).unwrap();
    unsafe { libc::system(c_cmd.as_ptr()); }
}
`
	flows := Analyze(code, "/app/ffi.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for env::var -> libc::system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Command Injection via libc::execvp (CWE-78) ---

func TestRust_LibcExecvp_EnvVar(t *testing.T) {
	code := `
use std::env;
use std::ffi::CString;

fn replace_process() {
    let prog = env::var("USER_PROG").unwrap();
    let c_prog = CString::new(prog).unwrap();
    unsafe { libc::execvp(c_prog.as_ptr(), std::ptr::null()); }
}
`
	flows := Analyze(code, "/app/ffi.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for env::var -> libc::execvp")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Command Injection via nix::unistd::execvp (CWE-78) ---

func TestRust_NixExecvp_EnvVar(t *testing.T) {
	code := `
use std::env;
use std::ffi::CString;

fn nix_exec() {
    let prog = env::var("USER_PROG").unwrap();
    let c_prog = CString::new(prog).unwrap();
    nix::unistd::execvp(&c_prog, &[]).unwrap();
}
`
	flows := Analyze(code, "/app/unix.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for env::var -> nix::unistd::execvp")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Command Injection via the fluent Command builder chain (CWE-78) ---
//
// Regression test for the chained-builder false-negative:
// `Command::new("sh").arg("-c").arg(tainted).output()`. The tree-sitter
// receiver of the tainted `.arg` is the WHOLE inner chain text
// (`Command::new("sh").arg("-c")`), which previously matched neither the
// `std::process::Command` ObjectType nor any abbreviation heuristic, so no
// command sink fired. The matcher now recognizes the Command builder receiver
// shapes (constructor-chain text, `cmd`/`command` variable bindings).

func TestRust_CommandBuilderChain_Param(t *testing.T) {
	code := `
use std::process::Command;

pub fn run_shell_command(user_input: &str) {
    Command::new("sh")
        .arg("-c")
        .arg(user_input)
        .output()
        .expect("failed to execute");
}
`
	flows := Analyze(code, "/app/cmd.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for parameter -> Command::new(..).arg(..) builder chain")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_CommandBuilderChain_VarBinding(t *testing.T) {
	// Variable-bound builder: `let mut cmd = Command::new(..); cmd.arg("-c").arg(tainted)`.
	code := `
use std::env;
use std::process::Command;

fn handler() {
    let user_input = env::var("X").unwrap();
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(user_input).output().expect("x");
}
`
	flows := Analyze(code, "/app/cmd.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for cmd.arg(..) variable-bound builder chain")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Safe: the same builder chain on a clap Command must NOT fire ---
//
// clap's `Command::new(..).arg(Arg::new("name"))` uses the identical fluent
// shape but passes a constant builder, not user input. With no tainted
// argument there must be no command flow — proves the broadened receiver match
// is FP-safe (it only reports a SINK MATCH; a finding still needs taint).

func TestRust_CommandBuilderChain_Safe_ClapConstant(t *testing.T) {
	code := `
use std::process::Command;
use clap::Arg;

pub fn run_safe(user_input: &str) {
    let _unused = user_input;
    Command::new("ls")
        .arg("-la")
        .arg(Arg::new("verbose"))
        .output()
        .expect("x");
}
`
	flows := Analyze(code, "/app/cmd.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand {
			t.Errorf("unexpected command flow on constant/clap builder args: src=%s", f.Source.ID)
		}
	}
}

// --- Safe: shlex::try_quote(x).unwrap() sanitizer is seen through the unwrap ---
//
// Regression test for the Result-combinator peeling: the sanitizer call is
// wrapped in `.unwrap()`. Before peeling, the matcher only saw the opaque
// `unwrap` method and missed the `shlex::try_quote` sanitizer, so the tainted
// value reached the (now-matching) command sink and produced a false positive.

func TestRust_CommandBuilderChain_Safe_ShlexUnwrap(t *testing.T) {
	code := `
use std::env;
use std::process::Command;

fn handler() {
    let user_input = env::var("CMD_ARG").unwrap();
    let safe = shlex::try_quote(&user_input).unwrap();
    Command::new("sh").arg("-c").arg(safe.as_ref()).output().expect("x");
}
`
	flows := Analyze(code, "/app/cmd.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand {
			t.Errorf("unexpected command flow after shlex::try_quote(..).unwrap() sanitization: src=%s", f.Source.ID)
		}
	}
}

// --- Safe: sanitized command args (no finding expected) ---

func TestRust_CommandArgs_Safe_ShellEscape(t *testing.T) {
	code := `
use std::env;
use std::process::Command;

fn run_safe() {
    let input = env::var("USER_INPUT").unwrap();
    let safe = shell_escape::escape(input);
    let mut cmd = Command::new("echo");
    cmd.args(safe);
}
`
	flows := Analyze(code, "/app/runner.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand {
			t.Error("unexpected command injection flow after shell_escape sanitization")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
