package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Python command injection — asyncio, os.exec*, os.spawn*, pty.spawn
// =========================================================================

func TestPython_AsyncioCreateSubprocessShell(t *testing.T) {
	code := `
import asyncio
from flask import request

async def handler():
    cmd = request.args.get("cmd")
    proc = await asyncio.create_subprocess_shell(cmd)
    await proc.wait()
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for request.args -> asyncio.create_subprocess_shell()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_AsyncioCreateSubprocessShell_BareImport(t *testing.T) {
	code := `
from asyncio import create_subprocess_shell
from flask import request

async def handler():
    cmd = request.args.get("cmd")
    proc = await create_subprocess_shell(cmd)
    await proc.wait()
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for request.args -> create_subprocess_shell() (bare import)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_AsyncioCreateSubprocessExec(t *testing.T) {
	code := `
import asyncio
from flask import request

async def handler():
    binary = request.args.get("bin")
    proc = await asyncio.create_subprocess_exec(binary, "--flag")
    await proc.wait()
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for request.args -> asyncio.create_subprocess_exec()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_OsExecvp(t *testing.T) {
	code := `
import os

def handler():
    cmd = input()
    os.execvp(cmd, [cmd])
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for input() -> os.execvp()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_OsExecle(t *testing.T) {
	code := `
import os

def handler():
    path = input()
    os.execle(path, path, os.environ)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for input() -> os.execle()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_OsSpawnlp(t *testing.T) {
	code := `
import os
from flask import request

def handler():
    binary = request.args.get("bin")
    os.spawnlp(os.P_WAIT, binary, binary, "--version")
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for request.args -> os.spawnlp()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_PtySpawn(t *testing.T) {
	code := `
import pty

def handler():
    shell = input()
    pty.spawn(shell)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for input() -> pty.spawn()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPython_AsyncioShell_Sanitized_NoFlow(t *testing.T) {
	code := `
import asyncio
import shlex
from flask import request

async def handler():
    cmd = request.args.get("cmd")
    safe = shlex.quote(cmd)
    proc = await asyncio.create_subprocess_shell("echo " + safe)
    await proc.wait()
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand {
			t.Error("expected NO command injection flow when shlex.quote() sanitizes input")
		}
	}
}
