package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"

	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// C command-injection sink tests (CWE-78) for additional process-spawning
// primitives where the tainted path / argument vector / command line is NOT
// the first argument:
//   posix_spawn / posix_spawnp (path at arg 1, argv at arg 4),
//   GLib g_spawn_sync / g_spawn_async (argv at arg 1),
//   Windows ShellExecute (file/params at args 2-3),
//   Windows CreateProcess (application name / command line at args 0-1).
// All use an environment-variable source (getenv).
// =========================================================================

func TestC_Getenv_ToPosixSpawn(t *testing.T) {
	code := `
#include <stdlib.h>
#include <spawn.h>

void run_input(void) {
    char *path = getenv("USER_INPUT");
    pid_t pid;
    char *args[] = { path, NULL };
    posix_spawn(&pid, path, NULL, NULL, args, NULL);
}
`
	flows := Analyze(code, "/app/posix_spawn.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for getenv -> posix_spawn")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Getenv_ToPosixSpawnp(t *testing.T) {
	code := `
#include <stdlib.h>
#include <spawn.h>

void run_input(void) {
    char *prog = getenv("USER_INPUT");
    pid_t pid;
    char *args[] = { prog, NULL };
    posix_spawnp(&pid, prog, NULL, NULL, args, NULL);
}
`
	flows := Analyze(code, "/app/posix_spawnp.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for getenv -> posix_spawnp")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Getenv_ToGSpawnSync(t *testing.T) {
	code := `
#include <stdlib.h>
#include <glib.h>

void run_input(void) {
    char *prog = getenv("USER_INPUT");
    char *args[] = { prog, NULL };
    GError *err = NULL;
    g_spawn_sync(NULL, args, NULL, 0, NULL, NULL, NULL, NULL, NULL, &err);
}
`
	flows := Analyze(code, "/app/gspawn_sync_argv.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for getenv -> g_spawn_sync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Getenv_ToGSpawnAsync(t *testing.T) {
	code := `
#include <stdlib.h>
#include <glib.h>

void run_input(void) {
    char *prog = getenv("USER_INPUT");
    char *args[] = { prog, NULL };
    GError *err = NULL;
    g_spawn_async(NULL, args, NULL, 0, NULL, NULL, NULL, &err);
}
`
	flows := Analyze(code, "/app/gspawn_async_argv.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for getenv -> g_spawn_async")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Getenv_ToShellExecute(t *testing.T) {
	code := `
#include <stdlib.h>
#include <windows.h>

void run_input(void) {
    char *file = getenv("USER_INPUT");
    ShellExecuteA(NULL, "open", file, NULL, NULL, SW_SHOW);
}
`
	flows := Analyze(code, "/app/shellexec.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for getenv -> ShellExecuteA")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Getenv_ToCreateProcess(t *testing.T) {
	code := `
#include <stdlib.h>
#include <windows.h>

void run_input(void) {
    char *cmdline = getenv("USER_INPUT");
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}
`
	flows := Analyze(code, "/app/createprocess.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for getenv -> CreateProcessA")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative control: constant arguments to the new spawn sinks must NOT
// produce a command-injection flow (no tainted input reaches the sink).
func TestC_ConstantSpawn_NoFlow(t *testing.T) {
	code := `
#include <stdlib.h>
#include <spawn.h>

void run_constant(void) {
    char *unused = getenv("UNUSED");
    pid_t pid;
    char *args[] = { "/bin/ls", "-la", NULL };
    posix_spawn(&pid, "/bin/ls", NULL, NULL, args, NULL);
}
`
	flows := Analyze(code, "/app/safe_spawn.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("did not expect command injection flow for constant posix_spawn arguments")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
