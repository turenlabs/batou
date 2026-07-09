package hook_test

import (
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/hook"
)

// ---------------------------------------------------------------------------
// Test plumbing for the os.Stdin / os.Stdout backed functions.
//
// ReadInput, OutputPreTool, and OutputPostTool all read from / write to the
// process-level os.Stdin / os.Stdout. The existing test suite exercises the
// pure helpers only; these helpers swap the real fds for OS pipes so the I/O
// functions can be exercised end-to-end (real behavior, not mocks).
// ---------------------------------------------------------------------------

// withStdin replaces os.Stdin with a pipe carrying data for the duration of fn,
// then restores the original. The write end is closed before fn runs so that
// io.ReadAll observes EOF after consuming data (no deadlock).
func withStdin(t *testing.T, data string, fn func()) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stdin
	os.Stdin = r
	defer func() {
		os.Stdin = orig
		_ = r.Close()
	}()

	// Write the payload from a goroutine, then close so ReadAll sees EOF.
	go func() {
		_, _ = io.WriteString(w, data)
		_ = w.Close()
	}()

	fn()
}

// captureStdout replaces os.Stdout with a pipe, runs fn, and returns everything
// fn wrote to stdout. The original os.Stdout is restored before returning.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()

	fn()

	_ = w.Close()
	os.Stdout = orig
	out := <-done
	_ = r.Close()
	return out
}

// ---------------------------------------------------------------------------
// ReadInput
// ---------------------------------------------------------------------------

func TestReadInputValid(t *testing.T) {
	raw := `{
		"session_id": "ses-read-1",
		"cwd": "/proj",
		"hook_event_name": "PreToolUse",
		"tool_name": "Write",
		"tool_input": {"file_path": "/proj/main.go", "content": "package main"}
	}`

	var got *hook.Input
	var err error
	withStdin(t, raw, func() {
		got, err = hook.ReadInput()
	})

	if err != nil {
		t.Fatalf("ReadInput() error = %v", err)
	}
	if got == nil {
		t.Fatal("ReadInput() returned nil input")
	}
	if got.SessionID != "ses-read-1" {
		t.Errorf("SessionID = %q, want %q", got.SessionID, "ses-read-1")
	}
	if !got.IsPreToolUse() {
		t.Error("expected IsPreToolUse() = true")
	}
	if !got.IsWriteOperation() {
		t.Error("expected IsWriteOperation() = true")
	}
	if got.ResolvePath() != "/proj/main.go" {
		t.Errorf("ResolvePath() = %q", got.ResolvePath())
	}
	if got.ResolveContent() != "package main" {
		t.Errorf("ResolveContent() = %q", got.ResolveContent())
	}
}

func TestReadInputEditEvent(t *testing.T) {
	raw := `{"hook_event_name":"PreToolUse","tool_name":"Edit","tool_input":{"file_path":"/a/b.go","old_string":"x","new_string":"y"}}`

	var got *hook.Input
	var err error
	withStdin(t, raw, func() {
		got, err = hook.ReadInput()
	})
	if err != nil {
		t.Fatalf("ReadInput() error = %v", err)
	}
	if !got.IsEditOperation() {
		t.Error("expected IsEditOperation() = true")
	}
	if got.ResolveContent() != "y" {
		t.Errorf("ResolveContent() = %q, want %q", got.ResolveContent(), "y")
	}
}

func TestReadInputMalformed(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"empty stdin", ""},
		{"not json", "this is not json"},
		{"truncated", `{"session_id":"x"`},
		{"trailing garbage", `{"session_id":"x"} not json`},
		{"array not object", `[1,2,3]`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got *hook.Input
			var err error
			withStdin(t, tt.raw, func() {
				got, err = hook.ReadInput()
			})
			if err == nil {
				t.Fatalf("ReadInput() error = nil, want a parse error for %q", tt.name)
			}
			if got != nil {
				t.Errorf("ReadInput() returned non-nil input %+v on error", got)
			}
			if !strings.Contains(err.Error(), "parsing hook input") {
				t.Errorf("error = %q, want it to mention %q", err.Error(), "parsing hook input")
			}
		})
	}
}

func TestReadInputJSONNull(t *testing.T) {
	// "null" is valid JSON and unmarshals into a zero-value Input without error.
	var got *hook.Input
	var err error
	withStdin(t, "null", func() {
		got, err = hook.ReadInput()
	})
	if err != nil {
		t.Fatalf("ReadInput() on JSON null error = %v, want nil", err)
	}
	if got == nil {
		t.Fatal("ReadInput() returned nil for JSON null")
	}
	if got.HookEventName != "" || got.ResolvePath() != "" {
		t.Errorf("expected zero-value Input from JSON null, got %+v", got)
	}
}

// TestReadInputStdinReadError exercises the io.ReadAll failure branch of
// ReadInput — the path where stdin itself errors before any JSON parsing can
// happen (e.g. a broken/closed descriptor). The malformed-input tests above
// all reach the json.Unmarshal error; this one is the *earlier* read error.
//
// To force a deterministic read failure we point os.Stdin at the read end of a
// pipe and close it before calling ReadInput. Reading from a closed *os.File
// returns os.ErrClosed ("file already closed"), which io.ReadAll surfaces.
func TestReadInputStdinReadError(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	_ = w.Close() // we never write; close the unused write end.

	orig := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = orig }()

	// Close the read end so the subsequent ReadInput read fails immediately.
	if cerr := r.Close(); cerr != nil {
		t.Fatalf("closing pipe read end: %v", cerr)
	}

	got, rerr := hook.ReadInput()
	if rerr == nil {
		t.Fatal("ReadInput() error = nil, want a stdin read error")
	}
	if got != nil {
		t.Errorf("ReadInput() returned non-nil input %+v on read error", got)
	}
	// ReadInput wraps read failures with the "reading stdin" prefix, distinct
	// from the "parsing hook input" prefix used for JSON errors.
	if !strings.Contains(rerr.Error(), "reading stdin") {
		t.Errorf("error = %q, want it to mention %q", rerr.Error(), "reading stdin")
	}
}

// ---------------------------------------------------------------------------
// OutputPreTool
// ---------------------------------------------------------------------------

func TestOutputPreToolAllow(t *testing.T) {
	var err error
	out := captureStdout(t, func() {
		err = hook.OutputPreTool("allow", "scan clean", "Batou: no findings")
	})
	if err != nil {
		t.Fatalf("OutputPreTool() error = %v", err)
	}

	var parsed hook.PreToolOutput
	if e := json.Unmarshal([]byte(out), &parsed); e != nil {
		t.Fatalf("stdout was not valid PreToolOutput JSON: %v (raw=%q)", e, out)
	}
	if parsed.HookSpecificOutput == nil {
		t.Fatal("hookSpecificOutput missing from emitted JSON")
	}
	hso := parsed.HookSpecificOutput
	if hso.HookEventName != "PreToolUse" {
		t.Errorf("hookEventName = %q, want PreToolUse", hso.HookEventName)
	}
	if hso.PermissionDecision != "allow" {
		t.Errorf("permissionDecision = %q, want allow", hso.PermissionDecision)
	}
	if hso.PermissionDecisionReason != "scan clean" {
		t.Errorf("permissionDecisionReason = %q", hso.PermissionDecisionReason)
	}
	if hso.AdditionalContext != "Batou: no findings" {
		t.Errorf("additionalContext = %q", hso.AdditionalContext)
	}
}

func TestOutputPreToolBlock(t *testing.T) {
	var err error
	out := captureStdout(t, func() {
		err = hook.OutputPreTool("block", "Critical SQLi", "BATOU-INJ-001")
	})
	if err != nil {
		t.Fatalf("OutputPreTool() error = %v", err)
	}
	var parsed hook.PreToolOutput
	if e := json.Unmarshal([]byte(out), &parsed); e != nil {
		t.Fatalf("invalid JSON: %v", e)
	}
	if parsed.HookSpecificOutput.PermissionDecision != "block" {
		t.Errorf("permissionDecision = %q, want block", parsed.HookSpecificOutput.PermissionDecision)
	}
}

func TestOutputPreToolEmptyFieldsOmitted(t *testing.T) {
	// decision/reason/context are all omitempty; with empty args only the
	// always-present hookEventName should remain inside hookSpecificOutput.
	out := captureStdout(t, func() {
		_ = hook.OutputPreTool("", "", "")
	})

	var parsed map[string]interface{}
	if e := json.Unmarshal([]byte(out), &parsed); e != nil {
		t.Fatalf("invalid JSON: %v (raw=%q)", e, out)
	}
	hso, ok := parsed["hookSpecificOutput"].(map[string]interface{})
	if !ok {
		t.Fatal("hookSpecificOutput missing")
	}
	if hso["hookEventName"] != "PreToolUse" {
		t.Errorf("hookEventName = %v, want PreToolUse", hso["hookEventName"])
	}
	for _, k := range []string{"permissionDecision", "permissionDecisionReason", "additionalContext"} {
		if _, exists := hso[k]; exists {
			t.Errorf("expected %q to be omitted when empty", k)
		}
	}
}

func TestOutputPreToolEndsWithNewline(t *testing.T) {
	// json.Encoder.Encode appends a trailing newline; the hook protocol emits
	// newline-delimited JSON, so confirm that contract holds.
	out := captureStdout(t, func() {
		_ = hook.OutputPreTool("allow", "ok", "")
	})
	if !strings.HasSuffix(out, "\n") {
		t.Errorf("expected trailing newline from OutputPreTool, got %q", out)
	}
}

// ---------------------------------------------------------------------------
// OutputPostTool
// ---------------------------------------------------------------------------

func TestOutputPostToolWithContext(t *testing.T) {
	var err error
	out := captureStdout(t, func() {
		err = hook.OutputPostTool("scan completed with 2 findings")
	})
	if err != nil {
		t.Fatalf("OutputPostTool() error = %v", err)
	}
	var parsed hook.PostToolOutput
	if e := json.Unmarshal([]byte(out), &parsed); e != nil {
		t.Fatalf("invalid JSON: %v (raw=%q)", e, out)
	}
	if parsed.AdditionalContext != "scan completed with 2 findings" {
		t.Errorf("additionalContext = %q", parsed.AdditionalContext)
	}
}

func TestOutputPostToolEmptyContextOmitted(t *testing.T) {
	out := captureStdout(t, func() {
		_ = hook.OutputPostTool("")
	})
	var parsed map[string]interface{}
	if e := json.Unmarshal([]byte(out), &parsed); e != nil {
		t.Fatalf("invalid JSON: %v (raw=%q)", e, out)
	}
	if _, exists := parsed["additionalContext"]; exists {
		t.Error("expected additionalContext to be omitted when empty")
	}
}

// ---------------------------------------------------------------------------
// BlockWrite — exercises os.Exit(2), so it must run in a subprocess.
//
// The canonical Go pattern: the test re-execs itself with an env flag; the
// child calls BlockWrite and is expected to terminate with exit code 2 and
// the message on stderr. The parent inspects the child's exit status/output.
// ---------------------------------------------------------------------------

func TestBlockWriteExitCodeAndMessage(t *testing.T) {
	if os.Getenv("BATOU_HOOK_TEST_BLOCKWRITE") == "1" {
		// Child process: emit a pre-tool JSON first (mirrors real usage where
		// OutputPreTool runs before BlockWrite), then block.
		_ = hook.OutputPreTool("block", "blocked by test", "ctx")
		hook.BlockWrite("BATOU-INJ-001: SQL injection detected\n")
		return // unreachable: BlockWrite calls os.Exit.
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestBlockWriteExitCodeAndMessage")
	cmd.Env = append(os.Environ(), "BATOU_HOOK_TEST_BLOCKWRITE=1")
	stdout, err := cmd.Output()

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected child to exit non-zero via os.Exit; err = %v", err)
	}
	if code := exitErr.ExitCode(); code != 2 {
		t.Errorf("child exit code = %d, want 2", code)
	}

	// The block message goes to stderr (captured by ExitError.Stderr).
	if !strings.Contains(string(exitErr.Stderr), "SQL injection detected") {
		t.Errorf("stderr = %q, want it to contain the block message", string(exitErr.Stderr))
	}

	// The pre-tool JSON emitted before the block must survive on stdout
	// (BlockWrite syncs stdout before exiting so prior output isn't lost).
	if !strings.Contains(string(stdout), "PreToolUse") {
		t.Errorf("stdout = %q, want the pre-block PreToolUse JSON to be preserved", string(stdout))
	}
}

func TestBlockWriteEmptyMessage(t *testing.T) {
	if os.Getenv("BATOU_HOOK_TEST_BLOCKWRITE_EMPTY") == "1" {
		hook.BlockWrite("")
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestBlockWriteEmptyMessage")
	cmd.Env = append(os.Environ(), "BATOU_HOOK_TEST_BLOCKWRITE_EMPTY=1")
	err := cmd.Run()

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected non-zero exit, got err = %v", err)
	}
	if code := exitErr.ExitCode(); code != 2 {
		t.Errorf("exit code = %d, want 2 even with empty message", code)
	}
}
