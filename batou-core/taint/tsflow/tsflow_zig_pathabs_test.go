package tsflow

// Tests for Zig std.fs absolute-path sinks (CWE-22) and environment
// manipulation sinks (CWE-78). Zig uses the regex-based taint.Analyze
// engine (no tree-sitter grammar registered), so these tests exercise
// the catalog patterns directly.

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Zig — Path traversal via std.fs.copyFileAbsolute (CWE-22)
// =========================================================================

func TestZig_PathTraversal_CopyFileAbsolute(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

pub fn handler(request: zap.Request) !void {
    const dest = request.getParamSlice("dest");
    try std.fs.copyFileAbsolute("/srv/data.txt", dest, .{});
}
`
	flows := taint.Analyze(code, "/app/files.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected FileWrite flow for getParamSlice -> std.fs.copyFileAbsolute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — Path traversal via std.fs.accessAbsolute (CWE-22)
// =========================================================================

func TestZig_PathTraversal_AccessAbsolute(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

pub fn handler(request: zap.Request) !void {
    const path = request.getParamSlice("path");
    try std.fs.accessAbsolute(path, .{});
}
`
	flows := taint.Analyze(code, "/app/probe.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected FileRead flow for getParamSlice -> std.fs.accessAbsolute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — Path traversal via std.fs.openDirAbsolute (CWE-22)
// =========================================================================

func TestZig_PathTraversal_OpenDirAbsolute(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

pub fn handler(request: zap.Request) !void {
    const dir_path = request.getParamSlice("dir");
    var d = try std.fs.openDirAbsolute(dir_path, .{});
    defer d.close();
}
`
	flows := taint.Analyze(code, "/app/dirs.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected FileRead flow for getParamSlice -> std.fs.openDirAbsolute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — Arbitrary tree deletion via std.fs.deleteTreeAbsolute (CWE-22)
// =========================================================================

func TestZig_PathTraversal_DeleteTreeAbsolute(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

pub fn handler(request: zap.Request) !void {
    const victim = request.getParamSlice("target");
    try std.fs.deleteTreeAbsolute(victim);
}
`
	flows := taint.Analyze(code, "/app/purge.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected FileWrite flow for getParamSlice -> std.fs.deleteTreeAbsolute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — Path traversal via std.fs.renameAbsolute (CWE-22)
// =========================================================================

func TestZig_PathTraversal_RenameAbsolute(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

pub fn handler(request: zap.Request) !void {
    const src = request.getParamSlice("from");
    const dst = request.getParamSlice("to");
    try std.fs.renameAbsolute(src, dst);
}
`
	flows := taint.Analyze(code, "/app/mv.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected FileWrite flow for getParamSlice -> std.fs.renameAbsolute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — Environment injection via std.posix.setenv (CWE-78)
// =========================================================================

func TestZig_EnvInjection_PosixSetenv(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

pub fn handler(request: zap.Request) !void {
    const value = request.getParamSlice("ld_preload");
    try std.posix.setenv("LD_PRELOAD", value, 1);
}
`
	flows := taint.Analyze(code, "/app/config.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected Command flow for getParamSlice -> std.posix.setenv (LD_PRELOAD hijack)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — Environment injection via std.posix.unsetenv (CWE-78)
// =========================================================================

func TestZig_EnvInjection_PosixUnsetenv(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

pub fn handler(request: zap.Request) !void {
    const name = request.getParamSlice("var");
    try std.posix.unsetenv(name);
}
`
	flows := taint.Analyze(code, "/app/config.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected Command flow for getParamSlice -> std.posix.unsetenv")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — Environment injection via std.c.setenv (CWE-78)
// =========================================================================

func TestZig_EnvInjection_CSetenv(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

pub fn handler(request: zap.Request) !void {
    const path = request.getParamSlice("path");
    _ = std.c.setenv("PATH", path, 1);
}
`
	flows := taint.Analyze(code, "/app/config.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected Command flow for getParamSlice -> std.c.setenv (PATH hijack)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — Environment injection via std.c.putenv (CWE-78)
// =========================================================================

func TestZig_EnvInjection_CPutenv(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

pub fn handler(request: zap.Request) !void {
    const assignment = request.getParamSlice("kv");
    _ = std.c.putenv(assignment);
}
`
	flows := taint.Analyze(code, "/app/config.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected Command flow for getParamSlice -> std.c.putenv")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — Safe: hardcoded absolute path to copyFileAbsolute (no flow expected)
// =========================================================================

func TestZig_PathTraversal_CopyFileAbsolute_Safe(t *testing.T) {
	code := `
const std = @import("std");

pub fn backup() !void {
    try std.fs.copyFileAbsolute("/srv/data.txt", "/srv/backup/data.txt", .{});
}
`
	flows := taint.Analyze(code, "/app/backup.zig", rules.LangZig)
	if hasZigTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected NO FileWrite flow for hardcoded-path copyFileAbsolute")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — Arbitrary file deletion via std.fs.deleteFileAbsolute (CWE-22)
// =========================================================================

func TestZig_PathTraversal_DeleteFileAbsolute(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

pub fn handler(request: zap.Request) !void {
    const victim = request.getParamSlice("file");
    try std.fs.deleteFileAbsolute(victim);
}
`
	flows := taint.Analyze(code, "/app/rm.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected FileWrite flow for getParamSlice -> std.fs.deleteFileAbsolute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — Arbitrary directory deletion via std.fs.deleteDirAbsolute (CWE-22)
// =========================================================================

func TestZig_PathTraversal_DeleteDirAbsolute(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

pub fn handler(request: zap.Request) !void {
    const victim = request.getParamSlice("dir");
    try std.fs.deleteDirAbsolute(victim);
}
`
	flows := taint.Analyze(code, "/app/rmdir.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected FileWrite flow for getParamSlice -> std.fs.deleteDirAbsolute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — Path traversal via std.fs.makeDirAbsolute (CWE-22)
// =========================================================================

func TestZig_PathTraversal_MakeDirAbsolute(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

pub fn handler(request: zap.Request) !void {
    const new_dir = request.getParamSlice("dir");
    try std.fs.makeDirAbsolute(new_dir);
}
`
	flows := taint.Analyze(code, "/app/mkdir.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected FileWrite flow for getParamSlice -> std.fs.makeDirAbsolute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — Symlink attack via std.fs.symLinkAbsolute (CWE-59)
// =========================================================================

func TestZig_SymlinkAttack_SymLinkAbsolute(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

pub fn handler(request: zap.Request) !void {
    const target = request.getParamSlice("target");
    try std.fs.symLinkAbsolute(target, "/tmp/link", .{});
}
`
	flows := taint.Analyze(code, "/app/ln.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected FileWrite flow for getParamSlice -> std.fs.symLinkAbsolute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — Path traversal via std.fs.updateFileAbsolute (CWE-22)
// =========================================================================

func TestZig_PathTraversal_UpdateFileAbsolute(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

pub fn handler(request: zap.Request) !void {
    const dest = request.getParamSlice("dest");
    _ = try std.fs.updateFileAbsolute("/srv/data.txt", dest, .{});
}
`
	flows := taint.Analyze(code, "/app/update.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected FileWrite flow for getParamSlice -> std.fs.updateFileAbsolute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — Permission escalation via std.posix.fchmodat (CWE-732)
// =========================================================================

func TestZig_PermsEscalation_PosixFchmodat(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

pub fn handler(request: zap.Request, dirfd: std.posix.fd_t) !void {
    const relpath = request.getParamSlice("path");
    try std.posix.fchmodat(dirfd, relpath, 0o777, 0);
}
`
	flows := taint.Analyze(code, "/app/chmod.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected FileWrite flow for getParamSlice -> std.posix.fchmodat")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — Ownership hijack via std.posix.fchown (CWE-732)
// =========================================================================

func TestZig_OwnershipHijack_PosixFchown(t *testing.T) {
	code := `
const std = @import("std");
const zap = @import("zap");

pub fn handler(request: zap.Request, fd: std.posix.fd_t) !void {
    const uid = request.getParamSlice("uid");
    try std.posix.fchown(fd, uid, null);
}
`
	flows := taint.Analyze(code, "/app/chown.zig", rules.LangZig)
	if !hasZigTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected FileWrite flow for getParamSlice -> std.posix.fchown")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Zig — Safe: hardcoded paths to new *Absolute sinks (no flow expected)
// =========================================================================

func TestZig_PathTraversal_NewAbsolute_Safe(t *testing.T) {
	code := `
const std = @import("std");

pub fn housekeeping() !void {
    try std.fs.deleteFileAbsolute("/var/cache/app/stale.tmp");
    try std.fs.deleteDirAbsolute("/var/cache/app/empty");
    try std.fs.makeDirAbsolute("/var/cache/app/new");
    try std.fs.symLinkAbsolute("/opt/app/current", "/opt/app/link", .{});
    _ = try std.fs.updateFileAbsolute("/srv/src.txt", "/srv/dst.txt", .{});
}
`
	flows := taint.Analyze(code, "/app/housekeeping.zig", rules.LangZig)
	if hasZigTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected NO FileWrite flow for hardcoded paths on new *Absolute sinks")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
