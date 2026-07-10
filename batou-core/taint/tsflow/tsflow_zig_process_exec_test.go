package tsflow

// Zig has no tree-sitter grammar registered, so taint.Analyze falls through to
// the regex-based engine (see tsflow_zig_test.go). These tests exercise the
// std.process.execv / std.process.execve command-injection sinks via that
// engine, mirroring the existing Zig taint tests (taint.Analyze + the shared
// hasZigTaintFlow helper).
//
// std.process.execv(allocator, argv) and std.process.execve(allocator, argv,
// env_map) replace the current process image and resolve the executable
// through PATH (argv[0] is the program). A tainted argv slice is therefore an
// OS command-injection sink (CWE-78). The dangerous argument is argv (index 1;
// allocator is index 0).

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Zig — command injection via std.process.execv (CWE-78)
// =========================================================================

func TestZig_CommandInjection_ProcessExecv(t *testing.T) {
	code := `
const std = @import("std");

fn handler(request: zap.Request, allocator: std.mem.Allocator) !void {
    const cmd = request.getParamSlice("cmd");
    const argv = [_][]const u8{ "/bin/sh", "-c", cmd };
    try std.process.execv(allocator, &argv);
}
`
	flows := taint.Analyze(code, "/app/exec.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for getParamSlice -> std.process.execv")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — command injection via std.process.execve (CWE-78)
// =========================================================================

func TestZig_CommandInjection_ProcessExecve(t *testing.T) {
	code := `
const std = @import("std");

fn handler(request: zap.Request, allocator: std.mem.Allocator) !void {
    const program = request.getParamSlice("program");
    const argv = [_][]const u8{ program };
    try std.process.execve(allocator, &argv, null);
}
`
	flows := taint.Analyze(code, "/app/exec.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for getParamSlice -> std.process.execve")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — safe: constant argv to std.process.execv must NOT flow (CWE-78)
// =========================================================================

func TestZig_CommandInjection_ProcessExecv_SafeConstant(t *testing.T) {
	code := `
const std = @import("std");

fn run_fixed(allocator: std.mem.Allocator) !void {
    const argv = [_][]const u8{ "/bin/ls", "-la" };
    try std.process.execv(allocator, &argv);
}
`
	flows := taint.Analyze(code, "/app/exec_safe.zig", rules.LangZig)
	if hasZigTaintFlow(flows, taint.SnkCommand) {
		t.Error("did not expect a command flow for a constant argv to std.process.execv")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
