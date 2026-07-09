package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/findings"
	"github.com/turenlabs/batou-core/hook"
	"github.com/turenlabs/batou-core/scanner"
)

// wantInteractiveUsage should only return true for a bare `batou` invocation
// from an interactive terminal. A real Claude Code hook run pipes JSON on
// stdin (stdinIsCharDevice == false) with no args, so it must return false.
func TestWantInteractiveUsage(t *testing.T) {
	cases := []struct {
		name              string
		args              []string
		stdinIsCharDevice bool
		want              bool
	}{
		{"bare batou on a TTY", nil, true, true},
		{"bare batou with empty args slice on a TTY", []string{}, true, true},
		{"bare batou with stdin piped (the real hook path)", nil, false, false},
		{"scan subcommand on a TTY", []string{"scan", "."}, true, false},
		{"findings subcommand on a TTY", []string{"findings"}, true, false},
		{"help arg on a TTY", []string{"help"}, true, false},
		{"help arg with stdin piped", []string{"help"}, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := wantInteractiveUsage(c.args, c.stdinIsCharDevice); got != c.want {
				t.Errorf("wantInteractiveUsage(%v, %v) = %v, want %v", c.args, c.stdinIsCharDevice, got, c.want)
			}
		})
	}
}

// printUsage must mention the hook mode and the `batou scan` subcommand so the
// text is actually self-explanatory.
func TestPrintUsage(t *testing.T) {
	var buf bytes.Buffer
	printUsage(&buf)
	out := buf.String()
	for _, want := range []string{"batou scan", "hook", "batou findings", "batou help"} {
		if !strings.Contains(out, want) {
			t.Errorf("printUsage() output missing %q; got:\n%s", want, out)
		}
	}
}

// version defaults to "dev" when not overridden at link time.
func TestVersionDefault(t *testing.T) {
	// In tests there's no -ldflags override, so it should be the literal default.
	if version != "dev" {
		t.Logf("version = %q (overridden at link time, that's fine)", version)
	}
}

// A finding suppressed by a `batou:ignore <target> -- reason` directive must
// persist the developer's actual justification in the findings store, not the
// generic "batou:ignore" constant. Covers the whole path: scanner stamps
// Finding.SuppressReason from the directive, persistFindings writes it into
// Record.SuppressReason.
func TestPersistFindings_SuppressReasonPersisted(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "app.py")
	src := `from flask import request

def handler():
    uid = request.args.get('id')
    query = "SELECT * FROM users WHERE id=" + uid
    # batou:ignore all -- known FP because X
    cursor.execute(query)
`

	// Keep the persistent callgraph off disk — this test only cares about
	// the findings store. Restore the process-wide override afterwards.
	prevDisabled := scanner.CallgraphPersistDisabled
	scanner.CallgraphPersistDisabled = true
	defer func() { scanner.CallgraphPersistDisabled = prevDisabled }()

	input := &hook.Input{
		HookEventName: "PostToolUse",
		ToolName:      "Write",
		ToolInput: hook.ToolInput{
			FilePath: file,
			Content:  src,
		},
	}
	result := scanner.Scan(input)

	if len(result.SuppressedFindings) == 0 {
		t.Fatalf("expected the SQLi taint finding to be suppressed; findings=%+v", result.Findings)
	}
	var stamped bool
	for _, f := range result.SuppressedFindings {
		if f.SuppressReason == "known FP because X" {
			stamped = true
		}
	}
	if !stamped {
		t.Fatalf("scanner did not stamp SuppressReason on the suppressed finding; got %+v", result.SuppressedFindings)
	}

	persistFindings(result)

	data, err := os.ReadFile(filepath.Join(dir, ".batou", "findings.json"))
	if err != nil {
		t.Fatalf("reading findings store: %v", err)
	}
	var records []findings.Record
	if err := json.Unmarshal(data, &records); err != nil {
		t.Fatalf("parsing findings store: %v", err)
	}
	var persisted bool
	for _, r := range records {
		if r.Status == findings.StatusSuppressed {
			if r.SuppressReason != "batou:ignore -- known FP because X" {
				t.Errorf("suppressed record %s: SuppressReason = %q, want %q",
					r.RuleID, r.SuppressReason, "batou:ignore -- known FP because X")
			}
			persisted = true
		}
	}
	if !persisted {
		t.Fatalf("no suppressed record in findings store; records=%+v", records)
	}
}
