package tsflow

// Zig has no tree-sitter grammar registered, so taint.Analyze (the regex
// engine) handles these flows — same as the other Zig tests in this package.
// These cover the subprocess-output sources added to zig_sources.go: the
// RETURN value of std.process.Child.run / std.ChildProcess.exec
// (RunResult.stdout / .stderr) is untrusted external content from a spawned
// program, which then flows into a command sink. The argv side of those calls
// is already modeled as a command-injection sink, so the positive fixtures use
// constant argv to isolate the source under test.

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

func TestZig_ChildRunOutput_CommandInjection(t *testing.T) {
	code := `
const std = @import("std");

fn handler(allocator: std.mem.Allocator) !void {
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "git", "log", "--format=%s" },
    });
    _ = std.c.system(result.stdout);
}
`
	flows := taint.Analyze(code, "/app/run.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for std.process.Child.run output -> std.c.system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_ChildProcessExecOutput_CommandInjection(t *testing.T) {
	code := `
const std = @import("std");

fn handler(allocator: std.mem.Allocator) !void {
    const out = try std.ChildProcess.exec(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "ls", "-la" },
    });
    _ = std.c.system(out.stdout);
}
`
	flows := taint.Analyze(code, "/app/legacy.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for std.ChildProcess.exec output -> std.c.system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative control: a constant string passed to the command sink must NOT
// produce a flow. This proves the flows above originate from the subprocess
// output source, not from some unrelated match on std.c.system.
func TestZig_SubprocessOutput_ConstantNoFlow(t *testing.T) {
	code := `
const std = @import("std");

fn handler() void {
    const cmd = "uptime";
    _ = std.c.system(cmd);
}
`
	flows := taint.Analyze(code, "/app/safe.zig", rules.LangZig)
	if hasZigTaintFlow(flows, taint.SnkCommand) {
		t.Error("did not expect a command-injection flow for a constant command string")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
