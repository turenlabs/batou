package tsflow

// Zig has no tree-sitter grammar registered, so taint.Analyze (the regex
// engine) handles these flows — same as the other Zig tests in this package.
// These cover the allocating file/stream read sources added to zig_sources.go
// (readToEndAlloc / readToEndAllocOptions / readUntilDelimiterOrEof[Alloc] /
// readBoundedBytes): untrusted file or stream content read into a buffer and
// then passed to a command sink.

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

func TestZig_ReadToEndAlloc_CommandInjection(t *testing.T) {
	code := `
const std = @import("std");

fn handler(file: std.fs.File, allocator: std.mem.Allocator) !void {
    const content = try file.readToEndAlloc(allocator, 4096);
    _ = std.c.system(content);
}
`
	flows := taint.Analyze(code, "/app/run.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for readToEndAlloc -> std.c.system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_ReadToEndAllocOptions_CommandInjection(t *testing.T) {
	code := `
const std = @import("std");

fn handler(file: std.fs.File, allocator: std.mem.Allocator) !void {
    const content = try file.readToEndAllocOptions(allocator, 4096, null, 1, null);
    _ = std.c.system(content);
}
`
	flows := taint.Analyze(code, "/app/run.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for readToEndAllocOptions -> std.c.system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_ReadUntilDelimiterOrEof_CommandInjection(t *testing.T) {
	code := `
const std = @import("std");

fn handler(reader: std.io.AnyReader, buf: []u8) !void {
    const line = try reader.readUntilDelimiterOrEof(buf, '\n');
    _ = std.c.system(line);
}
`
	flows := taint.Analyze(code, "/app/run.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for readUntilDelimiterOrEof -> std.c.system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_ReadUntilDelimiterOrEofAlloc_CommandInjection(t *testing.T) {
	code := `
const std = @import("std");

fn handler(reader: std.io.AnyReader, allocator: std.mem.Allocator) !void {
    const line = try reader.readUntilDelimiterOrEofAlloc(allocator, '\n', 4096);
    _ = std.c.system(line);
}
`
	flows := taint.Analyze(code, "/app/run.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for readUntilDelimiterOrEofAlloc -> std.c.system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestZig_ReadBoundedBytes_CommandInjection(t *testing.T) {
	code := `
const std = @import("std");

fn handler(reader: std.io.AnyReader) !void {
    const bytes = try reader.readBoundedBytes(4096);
    _ = std.c.system(bytes);
}
`
	flows := taint.Analyze(code, "/app/run.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for readBoundedBytes -> std.c.system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative control: a hardcoded constant command (no read source) must not
// produce a command-injection flow.
func TestZig_AllocReads_NoFlow_Constant(t *testing.T) {
	code := `
const std = @import("std");

fn handler() void {
    const content = "ls -la";
    _ = std.c.system(content);
}
`
	flows := taint.Analyze(code, "/app/run.zig", rules.LangZig)
	if hasZigTaintFlow(flows, taint.SnkCommand) {
		t.Error("did not expect a command-injection flow for a constant command string")
	}
}
