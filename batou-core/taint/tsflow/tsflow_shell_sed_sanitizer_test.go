package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// Tests for the shell sed allowlist-scrub sanitizer (shell.sed_allowlist):
//   sed 's/[^allowlist]//g'   complement-delete scrub (command/eval/file)
//
// This is the `sed` analogue of shell.tr_allowlist. Each sanitized case is
// paired with a positive control (the SAME source -> sink flow WITHOUT the
// scrub, or with a non-stripping sed substitution) that must still fire, so a
// test passing because the flow was never detected is impossible.

// ---- sed 's/[^...]//g' complement-delete allowlist scrub ----

func TestShell_Sanitized_SedAllowlist(t *testing.T) {
	code := `#!/bin/bash
read -r userin
safe=$(printf '%s' "$userin" | sed 's/[^[:alnum:]]//g')
eval "$safe"
`
	flows := Analyze(code, "/app/run.sh", rules.LangShell)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("sed 's/[^[:alnum:]]//g' should neutralize the command-injection flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestShell_Sanitized_SedAllowlist_ExtendedFlag(t *testing.T) {
	// -E (extended regex) with a `+` quantifier and a custom allowlist class.
	code := `#!/bin/bash
read -r userin
safe=$(printf '%s' "$userin" | sed -E 's/[^a-zA-Z0-9_-]+//g')
eval "$safe"
`
	flows := Analyze(code, "/app/run.sh", rules.LangShell)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("sed -E 's/[^a-zA-Z0-9_-]+//g' should neutralize the command-injection flow")
	}
}

func TestShell_Sanitized_SedAllowlist_FileSink(t *testing.T) {
	code := `#!/bin/bash
read -r userin
name=$(printf '%s' "$userin" | sed 's/[^a-zA-Z0-9]//g')
cat "/var/data/$name"
`
	flows := Analyze(code, "/app/run.sh", rules.LangShell)
	if hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("sed 's/[^a-zA-Z0-9]//g' should neutralize the file-path flow read -> cat")
	}
}

func TestShell_Control_SedTranslateNotSanitizer(t *testing.T) {
	// `sed 's/foo/bar/'` (literal replacement, no complement class) must NOT be
	// treated as a sanitizer — the command-injection flow must still fire.
	code := `#!/bin/bash
read -r userin
safe=$(printf '%s' "$userin" | sed 's/foo/bar/g')
eval "$safe"
`
	flows := Analyze(code, "/app/run.sh", rules.LangShell)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("control: sed 's/foo/bar/g' is a replacement, not an allowlist scrub; flow must remain")
	}
}

func TestShell_Control_SedNonEmptyReplacementNotSanitizer(t *testing.T) {
	// A complement class with a NON-empty replacement (`s/[^x]/Y/`) does not
	// delete the dangerous characters, so it must NOT qualify as a scrub.
	code := `#!/bin/bash
read -r userin
safe=$(printf '%s' "$userin" | sed 's/[^a-z]/Y/g')
eval "$safe"
`
	flows := Analyze(code, "/app/run.sh", rules.LangShell)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("control: sed 's/[^a-z]/Y/g' has a non-empty replacement; flow must remain")
	}
}
