package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Zig — numeric-coercion & enum-allowlist sanitizers for command injection.
//
// Zig has no registered tree-sitter grammar, so it runs the regex-fallback
// taint engine (taint.Analyze). The Pattern field is what matches; these
// tests confirm each new sanitizer neutralizes a SnkCommand flow.
// =========================================================================

// Baseline: user input flows straight into std.os.execve → command-injection.
func TestZig_Command_Unsanitized_Coercion(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

fn handler(request: zap.Request) void {
    const arg = request.getParamSlice("arg");
    std.os.execve(arg, &.{}, &.{});
}
`
	flows := taint.Analyze(code, "/app/run.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected Command flow when user input goes directly to std.os.execve")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// std.meta.stringToEnum maps the untrusted string to a fixed enum allowlist.
func TestZig_Command_Sanitized_StringToEnum(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

const Mode = enum { start, stop, restart };

fn handler(request: zap.Request) void {
    const raw = request.getParamSlice("mode");
    const mode = std.meta.stringToEnum(Mode, raw) orelse return;
    std.os.execve(mode, &.{}, &.{});
}
`
	flows := taint.Analyze(code, "/app/run.zig", rules.LangZig)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand {
			t.Error("expected NO Command flow when std.meta.stringToEnum is used")
		}
	}
}

// std.fmt.parseIntSizeSuffix coerces the string to a usize.
func TestZig_Command_Sanitized_ParseIntSizeSuffix(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

fn handler(request: zap.Request) void {
    const raw = request.getParamSlice("size");
    const n = std.fmt.parseIntSizeSuffix(raw, 10) catch return;
    std.os.execve(n, &.{}, &.{});
}
`
	flows := taint.Analyze(code, "/app/run.zig", rules.LangZig)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand {
			t.Error("expected NO Command flow when std.fmt.parseIntSizeSuffix is used")
		}
	}
}

// std.fmt.charToDigit coerces a single char to its numeric digit value.
func TestZig_Command_Sanitized_CharToDigit(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

fn handler(request: zap.Request) void {
    const raw = request.getParamSlice("d");
    const digit = std.fmt.charToDigit(raw[0], 10) catch return;
    std.os.execve(digit, &.{}, &.{});
}
`
	flows := taint.Analyze(code, "/app/run.zig", rules.LangZig)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand {
			t.Error("expected NO Command flow when std.fmt.charToDigit is used")
		}
	}
}

// Negative control: a non-coercing pass-through (std.mem.span) must NOT
// neutralize the flow — confirms the tests above aren't vacuously passing.
func TestZig_Command_Sanitized_NegativeControl(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

fn handler(request: zap.Request) void {
    const raw = request.getParamSlice("arg");
    const arg = std.mem.span(raw);
    std.os.execve(arg, &.{}, &.{});
}
`
	flows := taint.Analyze(code, "/app/run.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkCommand) {
		t.Error("negative control: expected Command flow to survive a non-sanitizing pass-through (std.mem.span)")
	}
}
