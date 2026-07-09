package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Swift — ShellOut + POSIX spawn/exec command-execution sinks (CWE-78)
// =========================================================================
//
// Swift already models Process/NSTask, system(), popen() and Process.run().
// This file covers the new command-execution sinks: the widely-used ShellOut
// package (johnsundell/ShellOut), which runs everything through `/bin/bash
// -c`, and the low-level POSIX process-launch primitives posix_spawn /
// posix_spawnp / execv / execve / execvp bridged from Glibc/Darwin. In each
// test a Vapor request value (swift.vapor.req.query) flows into the command /
// executable-path argument of the new sink.

// --- ShellOut shellOut(to:) --------------------------------------------

func TestSwift_ShellOut_To_CommandInjection(t *testing.T) {
	code := `
import ShellOut
import Vapor

func handler(req: Request) throws {
    let name = req.query["name"]
    try shellOut(to: "echo \(name)")
}
`
	flows := Analyze(code, "/app/RunShell.swift", rules.LangSwift)
	if !hasFlowFromSource(flows, "swift.vapor.req.query", taint.SnkCommand) {
		t.Error("expected command-injection flow for req.query -> shellOut(to:)")
		for _, f := range flows {
			t.Logf("  flow: %s(%s) -> %s(%s)", f.Source.Category, f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- ShellOut shellOut(to:arguments:) — tainted argument ---------------
//
// ShellOut joins `to:` and `arguments:` into one un-escaped bash -c line, so
// a tainted value in the arguments array is equally injectable (DangerousArgs
// covers both arg 0 and arg 1).

func TestSwift_ShellOut_Arguments_CommandInjection(t *testing.T) {
	code := `
import ShellOut
import Vapor

func handler(req: Request) throws {
    let target = req.query["target"]
    try shellOut(to: "git", arguments: [target])
}
`
	flows := Analyze(code, "/app/RunShellArgs.swift", rules.LangSwift)
	if !hasFlowFromSource(flows, "swift.vapor.req.query", taint.SnkCommand) {
		t.Error("expected command-injection flow for req.query -> shellOut(to:arguments:)")
		for _, f := range flows {
			t.Logf("  flow: %s(%s) -> %s(%s)", f.Source.Category, f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- POSIX posix_spawn (tainted executable path at arg 1) --------------

func TestSwift_PosixSpawn_CommandInjection(t *testing.T) {
	code := `
import Glibc
import Vapor

func handler(req: Request) {
    let bin = req.query["bin"]
    var pid: pid_t = 0
    posix_spawn(&pid, bin, nil, nil, argv, environ)
}
`
	flows := Analyze(code, "/app/Spawn.swift", rules.LangSwift)
	if !hasFlowFromSource(flows, "swift.vapor.req.query", taint.SnkCommand) {
		t.Error("expected command-injection flow for req.query -> posix_spawn path")
		for _, f := range flows {
			t.Logf("  flow: %s(%s) -> %s(%s)", f.Source.Category, f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- POSIX execv (tainted executable path at arg 0) --------------------

func TestSwift_Execv_CommandInjection(t *testing.T) {
	code := `
import Glibc
import Vapor

func handler(req: Request) {
    let bin = req.query["bin"]
    execv(bin, argv)
}
`
	flows := Analyze(code, "/app/Execv.swift", rules.LangSwift)
	if !hasFlowFromSource(flows, "swift.vapor.req.query", taint.SnkCommand) {
		t.Error("expected command-injection flow for req.query -> execv path")
		for _, f := range flows {
			t.Logf("  flow: %s(%s) -> %s(%s)", f.Source.Category, f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Negative: constant commands + discarded source → no flow ----------

func TestSwift_CommandExec_NoFlow_OnConstants(t *testing.T) {
	code := `
import ShellOut
import Glibc
import Vapor

func warmCommands(req: Request) throws {
    let name = req.query["name"]
    _ = name
    try shellOut(to: "ls -la")
    var pid: pid_t = 0
    posix_spawn(&pid, "/bin/ls", nil, nil, nil, nil)
    execv("/bin/ls", nil)
}
`
	flows := Analyze(code, "/app/WarmCommands.swift", rules.LangSwift)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("did NOT expect SnkCommand flow for constant commands + discarded source")
		for _, f := range flows {
			t.Logf("  flow: %s(%s) -> %s(%s)", f.Source.Category, f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Registration sanity: new sink IDs are present in the catalog ------

func TestSwift_CommandExecSinks_Registered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangSwift)
	want := map[string]bool{
		"swift.shellout":    false,
		"swift.posix.spawn": false,
		"swift.posix.exec":  false,
	}
	for _, s := range cat.Sinks() {
		if _, ok := want[s.ID]; ok {
			want[s.ID] = true
			if s.Category != taint.SnkCommand {
				t.Errorf("sink %s: expected Category SnkCommand, got %v", s.ID, s.Category)
			}
			if s.CWEID != "CWE-78" {
				t.Errorf("sink %s: expected CWE-78, got %s", s.ID, s.CWEID)
			}
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("expected sink %s to be registered in the Swift catalog", id)
		}
	}
}
