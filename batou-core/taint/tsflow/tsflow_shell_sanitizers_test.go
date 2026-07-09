package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// Tests for shell command sanitizers added in cycle #1105:
//   shell.tr_allowlist   tr -cd/-dc   (allowlist scrub: command/eval/file)
//   shell.printf_d       printf %d/%i (numeric coercion: command/eval/file)
//
// Each sanitizer is verified against a positive control (the same source ->
// sink flow WITHOUT the sanitizer must still fire) so a test passing for the
// wrong reason (flow never detected) is impossible.

// ---- tr -cd / -dc complement-delete allowlist scrub ----

func TestShell_Sanitized_TrAllowlist(t *testing.T) {
	code := `#!/bin/bash
read -r userin
safe=$(printf '%s' "$userin" | tr -cd '[:alnum:]')
eval "$safe"
`
	flows := Analyze(code, "/app/run.sh", rules.LangShell)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("tr -cd '[:alnum:]' should neutralize the command-injection flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestShell_Sanitized_TrAllowlist_Dc(t *testing.T) {
	// -dc flag ordering must match the same as -cd.
	code := `#!/bin/bash
read -r userin
safe=$(printf '%s' "$userin" | tr -dc 'a-zA-Z0-9')
eval "$safe"
`
	flows := Analyze(code, "/app/run.sh", rules.LangShell)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("tr -dc 'a-zA-Z0-9' should neutralize the command-injection flow")
	}
}

func TestShell_Control_TrTranslateNotSanitizer(t *testing.T) {
	// `tr 'A-Z' 'a-z'` (case translation, no -c/-d) must NOT be treated as a
	// sanitizer — the command-injection flow must still be reported.
	code := `#!/bin/bash
read -r userin
safe=$(printf '%s' "$userin" | tr 'A-Z' 'a-z')
eval "$safe"
`
	flows := Analyze(code, "/app/run.sh", rules.LangShell)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("control: tr 'A-Z' 'a-z' is not an allowlist scrub; flow must remain")
	}
}

func TestShell_Sanitized_TrAllowlist_FileSink(t *testing.T) {
	code := `#!/bin/bash
read -r userin
name=$(printf '%s' "$userin" | tr -cd '[:alnum:]')
cat "/var/data/$name"
`
	flows := Analyze(code, "/app/run.sh", rules.LangShell)
	if hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("tr -cd should neutralize the file-path flow read -> cat")
	}
}

// ---- printf %d / %i numeric coercion ----

func TestShell_Sanitized_PrintfD(t *testing.T) {
	code := `#!/bin/bash
read -r userin
n=$(printf '%d' "$userin")
eval "echo $n"
`
	flows := Analyze(code, "/app/run.sh", rules.LangShell)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("printf percent-d should neutralize the command-injection flow (numeric coercion)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestShell_Control_PrintfStringNotSanitizer(t *testing.T) {
	// `printf '%s'` (string passthrough) must NOT be treated as a sanitizer.
	code := `#!/bin/bash
read -r userin
n=$(printf '%s' "$userin")
eval "echo $n"
`
	flows := Analyze(code, "/app/run.sh", rules.LangShell)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("control: printf percent-s is a passthrough, not a sanitizer; flow must remain")
	}
}
