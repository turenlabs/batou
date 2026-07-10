package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"

	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// C command-injection sink tests (CWE-78) for additional exec primitives
// where the tainted command/expansion string is the first argument:
//   wordexp, g_spawn_command_line_sync/async (GLib), WinExec, _wsystem,
//   _popen (Windows CRT). All use an environment-variable source (getenv).
// =========================================================================

func TestC_Getenv_ToWordexp(t *testing.T) {
	code := `
#include <stdlib.h>
#include <wordexp.h>

void expand_input(void) {
    char *cmd = getenv("USER_INPUT");
    wordexp_t p;
    wordexp(cmd, &p, 0);
}
`
	flows := Analyze(code, "/app/wordexp.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for getenv -> wordexp")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Getenv_ToGSpawnCommandLineSync(t *testing.T) {
	code := `
#include <stdlib.h>
#include <glib.h>

void run_input(void) {
    char *cmd = getenv("USER_INPUT");
    gchar *out = NULL;
    gchar *err = NULL;
    gint status = 0;
    g_spawn_command_line_sync(cmd, &out, &err, &status, NULL);
}
`
	flows := Analyze(code, "/app/gspawn_sync.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for getenv -> g_spawn_command_line_sync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Getenv_ToGSpawnCommandLineAsync(t *testing.T) {
	code := `
#include <stdlib.h>
#include <glib.h>

void run_input(void) {
    char *cmd = getenv("USER_INPUT");
    g_spawn_command_line_async(cmd, NULL);
}
`
	flows := Analyze(code, "/app/gspawn_async.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for getenv -> g_spawn_command_line_async")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Getenv_ToWinExec(t *testing.T) {
	code := `
#include <stdlib.h>
#include <windows.h>

void run_input(void) {
    char *cmd = getenv("USER_INPUT");
    WinExec(cmd, SW_HIDE);
}
`
	flows := Analyze(code, "/app/winexec.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for getenv -> WinExec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Getenv_ToWSystem(t *testing.T) {
	code := `
#include <stdlib.h>
#include <process.h>

void run_input(void) {
    char *cmd = getenv("USER_INPUT");
    _wsystem(cmd);
}
`
	flows := Analyze(code, "/app/wsystem.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for getenv -> _wsystem")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Getenv_ToWPopen(t *testing.T) {
	code := `
#include <stdlib.h>
#include <stdio.h>

void run_input(void) {
    char *cmd = getenv("USER_INPUT");
    FILE *fp = _popen(cmd, "r");
}
`
	flows := Analyze(code, "/app/wpopen.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for getenv -> _popen")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative control: a constant command string passed to the new sinks must
// NOT produce a command-injection flow (no tainted input reaches the sink).
func TestC_ConstantCommand_NoFlow(t *testing.T) {
	code := `
#include <stdlib.h>
#include <wordexp.h>

void run_constant(void) {
    char *cmd = getenv("UNUSED");
    wordexp_t p;
    wordexp("ls -la /tmp", &p, 0);
}
`
	flows := Analyze(code, "/app/safe_const.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("did not expect command injection flow for constant wordexp argument")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
