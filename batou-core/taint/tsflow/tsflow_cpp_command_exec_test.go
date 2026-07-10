package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// C++ additional command-execution sinks (CWE-78)
//
// Cross-platform process-spawning free functions not covered by the existing
// system()/popen()/exec*()/boost::process entries: POSIX posix_spawn /
// posix_spawnp / wordexp, GLib g_spawn_* / g_spawn_command_line_*, and the
// Windows WinExec / ShellExecute family. Each fixture flows a tainted
// command-line argument (argv[1]) into the new sink.
// =========================================================================

func cppCmdHasFlow(flows []taint.TaintFlow) bool {
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand {
			return true
		}
	}
	return false
}

func TestCPP_PosixSpawn_Command(t *testing.T) {
	code := `
#include <spawn.h>
void run(const char* argv[]) {
    std::string prog = argv[1];
    pid_t pid;
    char* args[] = {(char*)prog.c_str(), nullptr};
    posix_spawn(&pid, prog.c_str(), nullptr, nullptr, args, nullptr);
}
`
	flows := Analyze(code, "/app/spawn.cpp", rules.LangCPP)
	if !cppCmdHasFlow(flows) {
		t.Error("expected command-injection flow for argv -> posix_spawn")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%s) conf=%.2f", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCPP_PosixSpawnp_Command(t *testing.T) {
	code := `
#include <spawn.h>
void run(const char* argv[]) {
    std::string prog = argv[1];
    pid_t pid;
    char* args[] = {(char*)prog.c_str(), nullptr};
    posix_spawnp(&pid, prog.c_str(), nullptr, nullptr, args, nullptr);
}
`
	flows := Analyze(code, "/app/spawnp.cpp", rules.LangCPP)
	if !cppCmdHasFlow(flows) {
		t.Error("expected command-injection flow for argv -> posix_spawnp")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%s) conf=%.2f", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCPP_Wordexp_Command(t *testing.T) {
	code := `
#include <wordexp.h>
void run(const char* argv[]) {
    std::string input = argv[1];
    wordexp_t p;
    wordexp(input.c_str(), &p, 0);
}
`
	flows := Analyze(code, "/app/wordexp.cpp", rules.LangCPP)
	if !cppCmdHasFlow(flows) {
		t.Error("expected command-injection flow for argv -> wordexp")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%s) conf=%.2f", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCPP_GlibSpawnCommandLine_Command(t *testing.T) {
	code := `
#include <glib.h>
void run(const char* argv[]) {
    std::string cmd = argv[1];
    GError* err = nullptr;
    g_spawn_command_line_sync(cmd.c_str(), nullptr, nullptr, nullptr, &err);
}
`
	flows := Analyze(code, "/app/gspawn_cl.cpp", rules.LangCPP)
	if !cppCmdHasFlow(flows) {
		t.Error("expected command-injection flow for argv -> g_spawn_command_line_sync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%s) conf=%.2f", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCPP_GlibSpawn_Command(t *testing.T) {
	code := `
#include <glib.h>
void run(const char* argv[]) {
    std::string prog = argv[1];
    char* args[] = {(char*)prog.c_str(), nullptr};
    GError* err = nullptr;
    g_spawn_async(nullptr, args, nullptr, G_SPAWN_DEFAULT, nullptr, nullptr, nullptr, &err);
}
`
	flows := Analyze(code, "/app/gspawn.cpp", rules.LangCPP)
	if !cppCmdHasFlow(flows) {
		t.Error("expected command-injection flow for argv -> g_spawn_async")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%s) conf=%.2f", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCPP_WinExec_Command(t *testing.T) {
	code := `
#include <windows.h>
void run(const char* argv[]) {
    std::string cmd = argv[1];
    WinExec(cmd.c_str(), SW_SHOW);
}
`
	flows := Analyze(code, "/app/winexec.cpp", rules.LangCPP)
	if !cppCmdHasFlow(flows) {
		t.Error("expected command-injection flow for argv -> WinExec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%s) conf=%.2f", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCPP_ShellExecute_Command(t *testing.T) {
	code := `
#include <windows.h>
void run(const char* argv[]) {
    std::string file = argv[1];
    ShellExecuteA(nullptr, "open", file.c_str(), nullptr, nullptr, SW_SHOW);
}
`
	flows := Analyze(code, "/app/shellexec.cpp", rules.LangCPP)
	if !cppCmdHasFlow(flows) {
		t.Error("expected command-injection flow for argv -> ShellExecuteA")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%s) conf=%.2f", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

// Negative control: a constant (non-tainted) command line must NOT produce a
// command-injection flow, confirming the new sinks key on taint rather than
// firing on every call.
func TestCPP_PosixSpawn_Constant_NoFlow(t *testing.T) {
	code := `
#include <spawn.h>
void run() {
    const char* prog = "/bin/ls";
    pid_t pid;
    char* args[] = {(char*)"/bin/ls", nullptr};
    posix_spawn(&pid, prog, nullptr, nullptr, args, nullptr);
}
`
	flows := Analyze(code, "/app/safe_spawn.cpp", rules.LangCPP)
	if cppCmdHasFlow(flows) {
		t.Error("did not expect a command-injection flow for a constant posix_spawn target")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}
