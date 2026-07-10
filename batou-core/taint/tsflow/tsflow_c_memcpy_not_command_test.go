package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"

	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Regression: C memory-copy / socket-write sinks must NOT be reported as
// command_exec (CWE-78). They are buffer overflows (CWE-120, SnkMemory) and
// cleartext transmission (CWE-319, SnkNetwork) respectively.
//
// Real-world FP (smoke test, redis-redis/src): 25/33 findings were
// BATOU-TAINT-command_exec on memcpy/memmove/write — a memcpy is never an OS
// command execution. The C/C++ catalogs mislabeled these memory sinks as
// taint.SnkCommand. After the fix they carry taint.SnkMemory / taint.SnkNetwork
// while keeping their correct CWE, so the same dataflow is still flagged — it
// is no longer masquerading as command injection.
//
// Each test pins BOTH directions:
//   - the memory/network shape NO LONGER fires SnkCommand (the FP is gone)
//   - it DOES still fire its correct category (we tightened, did not disable)
// A separate TP test confirms a genuine system(userInput) still fires
// SnkCommand, proving command_exec detection is intact.
// =========================================================================

func sinkMethodFor(flows []taint.TaintFlow, cat taint.SinkCategory) string {
	for _, f := range flows {
		if f.Sink.Category == cat {
			return f.Sink.MethodName
		}
	}
	return ""
}

// memcpy of attacker-controlled bytes into a buffer — the dominant Redis FP
// shape (e.g. networking.c:378 `memcpy(buf, payload, len)`).
func TestC_Memcpy_TaintedSource_IsMemoryNotCommand(t *testing.T) {
	code := `
#include <string.h>
#include <stdlib.h>

void copy_payload(char *payload, size_t len) {
    char buf[256];
    memcpy(buf, payload, len);
}
`
	flows := Analyze(code, "/app/networking.c", rules.LangC)

	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Errorf("memcpy must NOT be reported as command_exec (CWE-78) — it is a buffer overflow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%s, cwe %s)", f.Source.Category, f.Sink.Category, f.Sink.MethodName, f.Sink.CWEID)
		}
	}
	if !hasTaintFlow(flows, taint.SnkMemory) {
		t.Errorf("memcpy with tainted source must still fire SnkMemory (memory_write / CWE-120) — detection must be tightened, not disabled")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%s, cwe %s)", f.Source.Category, f.Sink.Category, f.Sink.MethodName, f.Sink.CWEID)
		}
	}
}

// memmove variant (redis-cli.c:9001 in the smoke test).
func TestC_Memmove_TaintedSource_IsMemoryNotCommand(t *testing.T) {
	code := `
#include <string.h>

void shift(char *data, size_t n) {
    char buf[128];
    memmove(buf, data, n);
}
`
	flows := Analyze(code, "/app/redis-cli.c", rules.LangC)

	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Errorf("memmove must NOT be reported as command_exec (CWE-78)")
	}
	if !hasTaintFlow(flows, taint.SnkMemory) {
		t.Errorf("memmove with tainted source must still fire SnkMemory (memory_write / CWE-120)")
	}
}

// strcpy unbounded copy — CWE-120 buffer overflow, never command exec.
func TestC_Strcpy_TaintedSource_IsMemoryNotCommand(t *testing.T) {
	code := `
#include <string.h>
#include <stdlib.h>

void store(char *input) {
    char buf[64];
    strcpy(buf, input);
}
`
	flows := Analyze(code, "/app/store.c", rules.LangC)

	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Errorf("strcpy must NOT be reported as command_exec (CWE-78)")
	}
	if !hasTaintFlow(flows, taint.SnkMemory) {
		t.Errorf("strcpy with tainted source must still fire SnkMemory (memory_write / CWE-120)")
	}
}

// POSIX write() of tainted bytes to an fd/socket — CWE-319 cleartext, not exec.
// (redis socket.c:136 / unix.c:134 in the smoke test.)
func TestC_Write_TaintedData_IsNetworkNotCommand(t *testing.T) {
	code := `
#include <unistd.h>

void emit(int fd, char *data, size_t len) {
    write(fd, data, len);
}
`
	flows := Analyze(code, "/app/socket.c", rules.LangC)

	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Errorf("POSIX write must NOT be reported as command_exec (CWE-78) — it is cleartext transmission")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%s, cwe %s)", f.Source.Category, f.Sink.Category, f.Sink.MethodName, f.Sink.CWEID)
		}
	}
	if !hasTaintFlow(flows, taint.SnkNetwork) {
		t.Errorf("write with tainted data must still fire SnkNetwork (network_write / CWE-319)")
	}
}

// TRUE POSITIVE guard: a genuine OS command execution (system(userInput)) MUST
// still fire SnkCommand/command_exec. This proves the relabel tightened the
// memory sinks without weakening real command-injection detection.
func TestC_System_TaintedInput_StillCommandExec(t *testing.T) {
	code := `
#include <stdlib.h>

void run(void) {
    char *user_input = getenv("USER_INPUT");
    system(user_input);
}
`
	flows := Analyze(code, "/app/exec.c", rules.LangC)

	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Errorf("system(user_input) must still fire SnkCommand (command_exec / CWE-78)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%s, cwe %s)", f.Source.Category, f.Sink.Category, f.Sink.MethodName, f.Sink.CWEID)
		}
	}
	if got := sinkMethodFor(flows, taint.SnkCommand); got != "system" {
		t.Errorf("expected the command_exec sink to be system, got %q", got)
	}
	// And it must NOT be misfiled as a memory sink.
	if hasTaintFlow(flows, taint.SnkMemory) {
		t.Errorf("system() must not be reported as a memory_write sink")
	}
}

// popen — the other real command sink — must also stay command_exec.
func TestC_Popen_TaintedInput_StillCommandExec(t *testing.T) {
	code := `
#include <stdio.h>
#include <stdlib.h>

void run(void) {
    char *user_input = getenv("USER_INPUT");
    FILE *fp = popen(user_input, "r");
}
`
	flows := Analyze(code, "/app/pipe.c", rules.LangC)

	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Errorf("popen(user_input) must still fire SnkCommand (command_exec / CWE-78)")
	}
}
